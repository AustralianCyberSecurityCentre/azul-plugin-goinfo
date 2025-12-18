package main

import (
	"context"
	debugBuildInfo "debug/buildinfo"
	"fmt"
	"log"
	"strings"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/plugin"
	"github.com/goretk/gore"
)

type GoInfoPlugin struct {
	// The last panic error from a recovered panic.
	panicError string
}

func (gi *GoInfoPlugin) GetName() string {
	return "GoInfo"
}

func (gi *GoInfoPlugin) GetVersion() string {
	return "2025.09.15"
}

func (gi *GoInfoPlugin) GetDescription() string {
	return "A plugin that uses the GoRE library to extract metadata from compiled Golang binaries"
}

func (gi *GoInfoPlugin) GetFeatures() []events.PluginEntityFeature {
	return []events.PluginEntityFeature{
		{Name: "go_compiler_flag", Type: events.FeatureString, Description: "A flag used at compile time of the go binary."},
		{Name: "go_build_id", Type: events.FeatureString, Description: "Go build ID"},
		{Name: "go_compiler_version", Type: events.FeatureString, Description: "Go compiler version"},
		{Name: "go_compiler_timestamp", Type: events.FeatureString, Description: "Go compiler timestamp"},
		{Name: "go_package", Type: events.FeatureString, Description: "User defined packages in a Go binary"},
		{Name: "go_package_function", Type: events.FeatureString, Description: "Functions in user defined packages"},
		{Name: "go_package_method", Type: events.FeatureString, Description: "Methods in user defined packages"},
		{Name: "go_vendor_package", Type: events.FeatureString, Description: "Packages from 3rd party vendors in a Go binary"},
		{Name: "go_file", Type: events.FeatureString, Description: "Files in a Go build"},
		{Name: "go_type", Type: events.FeatureString, Description: "Types in a Go binary"},
		{Name: "go_type_method", Type: events.FeatureString, Description: "Methods of a type"},
		{Name: "malformed", Type: events.FeatureString, Description: "File appears to be a corrupted PE file."},
	}
}

func (gi *GoInfoPlugin) GetDefaultSettings() *plugin.PluginSettings {
	defaultSettings := plugin.NewDefaultPluginSettings().WithContentFilterDataTypes([]string{
		// Windows exe
		"executable/windows/",
		// Non windows exe
		"executable/dll32",
		"executable/pe32",
		// Linux elf
		"executable/linux/elf64",
		"executable/linux/elf32",
		"executable/mach-o",
	})
	return defaultSettings
}

func handleGorePanic(gi *GoInfoPlugin) {
	goreRecover := recover()

	if goreRecover != nil {
		switch gorePanicMessage := goreRecover.(type) {
		case string:
			log.Printf("STRING PANIC %#v", gorePanicMessage)
			gi.panicError = gorePanicMessage
		default:
			log.Printf("PyGore paniced and the message couldn't be retrieved the recover value is %#v", gorePanicMessage)
			gi.panicError = "PyGore panic but the error couldn't be recovered."
		}
	} else {
		// If there is no panic clear the message.
		gi.panicError = ""
	}
}

func (gi *GoInfoPlugin) openGoreFile(sourcePath string) (*gore.GoFile, error) {
	defer handleGorePanic(gi)
	return gore.Open(sourcePath)
}

func (gi *GoInfoPlugin) Execute(context context.Context, job *plugin.Job, inputUtils *plugin.PluginInputUtils) *plugin.PluginError {
	contentFilePath, pluginErr := job.GetContentPath()
	if pluginErr != nil {
		return pluginErr
	}

	goFile, err := gi.openGoreFile(contentFilePath)
	// Opt out if the error is that the file is unsupported by pygore
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		return plugin.NewPluginOptOut(fmt.Sprintf("File could not be opened by pygore with message %s", err.Error()))
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "fail to read string table length") {
		pluginErr := job.AddFeature("malformed", fmt.Sprintf("PE file was corrupted and it's header couldn't be read with error %s", err.Error()))
		if pluginErr != nil {
			return pluginErr
		}
		return nil
	}
	if err != nil {
		return plugin.NewPluginError(plugin.ErrorException, "Could not be opened", "Pygore could not open the file").WithCausalError(err)
	}
	// goFile is only nil if openGoreFile paniced, so handle the panic message here.
	if goFile == nil {
		if gi.panicError == "Unsupported architecture" {
			return plugin.NewPluginOptOut(fmt.Sprintf("Gore paniced while trying to open the file with the panic message: '%s'", gi.panicError))
		}
		return plugin.NewPluginError(plugin.ErrorException, "Pygore Panic", fmt.Sprintf("Pygore paniced with a panic message: '%s'", gi.panicError))
	}
	defer goFile.Close()

	compilerVersion, err := goFile.GetCompilerVersion()
	if compilerVersion == nil || (err != nil && strings.ToLower(err.Error()) == "no goversion found") {
		return plugin.NewPluginOptOut("Not a go binary, no go version found.")
	}

	buildInfo, err := debugBuildInfo.ReadFile(contentFilePath)
	// Extract build info if the file is a valid go binary.
	if err == nil {
		for _, s := range buildInfo.Settings {
			pluginErr = job.AddFeatureWithExtra("go_compiler_flag", s.Value, &plugin.AddFeatureOptions{
				Label: s.Key,
			})
			if pluginErr != nil {
				return pluginErr
			}
		}
	}

	// Get core compiler information.
	pluginErr = job.AddFeature("go_build_id", goFile.BuildID)
	if pluginErr != nil {
		return pluginErr
	}
	if goFile.BuildInfo != nil && goFile.BuildInfo.Compiler != nil {
		pluginErr = job.AddFeature("go_compiler_version", goFile.BuildInfo.Compiler.Name)
		if pluginErr != nil {
			return pluginErr
		}
		pluginErr = job.AddFeature("go_compiler_timestamp", goFile.BuildInfo.Compiler.Timestamp)
		if pluginErr != nil {
			return pluginErr
		}
	}

	packageList, err := goFile.GetPackages()
	if err != nil {
		return plugin.NewPluginError(
			plugin.ErrorException,
			"Failed to get packages",
			"Failed to get the packages for the go binary.",
		).WithCausalError(err)
	}
	goPackageSet := map[string]interface{}{}
	// Get all the functions and methods in this package.
	for _, pkg := range packageList {
		pluginErr = job.AddFeature("go_package", pkg.Name)
		goPackageSet[pkg.Name] = nil
		if pluginErr != nil {
			return pluginErr
		}
		if pkg.Filepath != "." {
			pluginErr = job.AddFeature("go_file", pkg.Filepath)
			if pluginErr != nil {
				return pluginErr
			}
		}
		// Add package functions
		for _, pkgFunc := range pkg.Functions {
			pluginErr = job.AddFeatureWithExtra(
				"go_package_function",
				pkgFunc.Name,
				&plugin.AddFeatureOptions{
					Label:  pkgFunc.PackageName,
					Offset: pkgFunc.Offset,
					Size:   pkgFunc.End - pkgFunc.Offset,
				},
			)
			if pluginErr != nil {
				return pluginErr
			}
		}
		// Add package methods
		for _, pkgMethods := range pkg.Methods {
			pluginErr = job.AddFeatureWithExtra(
				"go_package_method",
				pkgMethods.Name,
				&plugin.AddFeatureOptions{
					Label:  pkgMethods.PackageName,
					Offset: pkgMethods.Offset,
					Size:   pkgMethods.End - pkgMethods.Offset,
				},
			)
			if pluginErr != nil {
				return pluginErr
			}
		}
	}
	// Get all the vendor package names.
	vendorPackages, err := goFile.GetVendors()
	if err != nil {
		return plugin.NewPluginError(
			plugin.ErrorException,
			"Failed to get vendor packages",
			"Failed to get the vendor packages for the go binary.",
		).WithCausalError(err)
	}
	for _, vendorPackage := range vendorPackages {
		pluginErr = job.AddFeature("go_vendor_package", vendorPackage.Name)
		if pluginErr != nil {
			return pluginErr
		}
	}

	// Add User definied GoTypes.
	goTypes, err := goFile.GetTypes()
	if err != nil {
		return plugin.NewPluginError(
			plugin.ErrorException,
			"Failed to get GoTypes",
			"Failed to get the GoTypes for the go binary.",
		).WithCausalError(err)
	}
	for _, goType := range goTypes {
		/*
			This will get all types defined in the binary including ones from standard libraries
			Somehow the get_packages() function only gets user defined packages, so we check the
			type's packagePath matches one of these to only get the user defined types as well
		*/
		_, ok := goPackageSet[goType.PackagePath]
		if !ok {
			continue
		}

		pluginErr = job.AddFeatureWithExtra(
			"go_type",
			goType.Name,
			&plugin.AddFeatureOptions{
				Label:  goType.Kind.String(),
				Offset: goType.Addr,
				Size:   uint64(goType.Length),
			},
		)
		if pluginErr != nil {
			return pluginErr
		}
		/*
			Type methods also have an offset value however it is an offset relative to
			a variable location in the binary, so excluding it in the below feature.
			Some of the methods below may be duplicated by the go_package_method
			feature anyway, which does extract the file offset
		*/
		for _, goTypeMethod := range goType.Methods {
			pluginErr = job.AddFeatureWithExtra(
				"go_type_method",
				goTypeMethod.Name,
				&plugin.AddFeatureOptions{Label: goType.Name},
			)
			if pluginErr != nil {
				return pluginErr
			}
		}
	}
	return nil
}

func main() {
	pr := plugin.NewPluginRunner(&GoInfoPlugin{})
	pr.Run()
}
