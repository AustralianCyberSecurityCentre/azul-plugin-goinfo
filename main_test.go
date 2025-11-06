package main

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/plugin"
)

func baseRunTest(t *testing.T, sha256 string, fileDescription string, expectedResult *plugin.TestJobResult) {
	pr := plugin.NewPluginRunner(&GoInfoPlugin{})
	result := pr.RunTest(t, &plugin.RunTestOptions{
		DownloadSha256: sha256,
	}, fileDescription)
	result.AssertJobResultEqual(t, expectedResult)
}

func TestInvalidInput(t *testing.T) {
	// Check Pdf file (not an exe)
	baseRunTest(t, "bd6d8dc6824df22afa6b4366a3296478bc551343897a01793fff501c3535aafb",
		"PDF",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "File could not be opened by pygore with message unsupported file",
		})

	// Check Jpg file (not an exe)
	baseRunTest(t, "e4d8c2da9bd198a247ebf88903ebeb21dad0fc89b726058cd3296aa754e900f6",
		"JPG",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "File could not be opened by pygore with message unsupported file",
		})

	// Check Rar file (not an exe)
	baseRunTest(t, "5f93517337b8f8ab046a3116ddbe70dddcf089e5b807771de2a6b71b1881bc04",
		"RAR",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "File could not be opened by pygore with message unsupported file",
		})
}

func TestFileThatsTooSmall(t *testing.T) {
	baseRunTest(t, "996c64810a426cacf9b9de8d916d7e0e36fc4ac5dccdb9e5ed0c62aa4d44ff00",
		"Benign 16byte test file.", &plugin.TestJobResult{
			Status:  "opt-out",
			Message: "File could not be opened by pygore with message unsupported file",
		})
}

func TestNonGoBinaries(t *testing.T) {
	// Test .NET executable binary
	baseRunTest(t, "a0120b1ec55e135859d2bcf82a4661c8ca57ab73c4fe487da328510f39925180",
		"Malicious dotnet Windows 32EXE.",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "Not a go binary, no go version found.",
		})

	// Test UPX packed binary (ece7d0ba67bbed16dec5cf71d0461434)
	baseRunTest(t, "7014914d81b6e0c554c9930ab3eaca37fa52276b746717d19d0f0b0fc12ead2a",
		"Malicious Windows EXE32 that is UPX packed.",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "Not a go binary, no go version found.",
		})

	// Test (non-Go) DLL (d51a2901bfa711fac4f138a28e69e194)
	baseRunTest(t, "dfbc7008e593f9ed6444bafa6cbd6cd7abfea7ed388d56740b4ba3db0f54b5d0",
		"Malicious Windows DLL32.",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "Not a go binary, no go version found.",
		})

	// Test (non-Go) ELF binary (3f4d697076200be482c054618a372a01)
	baseRunTest(t, "623ce6bf1153a26763babdf611838bd0520f0c96111a6d5bd34897a39e9f27d3",
		"Malicious ELF32.",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "Not a go binary, no go version found.",
		})

	// Test (non-Go) Mach-O binary (6fb595727e6501db667c44fcf2a805bf)
	baseRunTest(t, "e422e86c92e9e1b42cf2ab2344e8ff6d1e97a0c81406a08f90f77d9bd030980e",
		"Malicious Mach-O, malware family Canna.",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "Not a go binary, no go version found.",
		})
}

func TestGoDllInvalidHeader(t *testing.T) {
	baseRunTest(t, "022562f7f44bd8e87e550546ec45d66871d11b64a4ab85facdf23df1cd3c93bc",
		"golang Windows EXE32, with corrupted header.",
		&plugin.TestJobResult{
			Status: "completed",
			Events: []plugin.TestJobEvent{
				{
					Features: map[string][]plugin.TestBinaryEntityFeature{
						"malformed": {
							{
								Value: "PE file was corrupted and it's header couldn't be read with error error when parsing the PE file: fail to read string table length: EOF",
							},
						},
					},
				},
			},
		})
}

func TestGoPe(t *testing.T) {
	baseRunTest(t, "099d6d5dc10ab12e38bff88c7c622ddecace8fc3bf37062f7d19bb67d52d287a", "Malicious golang Windows EXE32.", &plugin.TestJobResult{
		Status: "completed",
		Events: []plugin.TestJobEvent{
			{
				Features: map[string][]plugin.TestBinaryEntityFeature{
					"go_build_id": {
						{
							Value: "THyJCsrrxDurShR_lQa-/NLfIvSXE3EVr4GaK6lHd/ym0JcumGoh8PSe7LgwLL/t31lXGfMUAPhGc-8ehfM",
						},
					},
					"go_compiler_timestamp": {
						{
							Value: "2020-08-11T19:01:57Z",
						},
					},
					"go_compiler_version": {
						{
							Value: "go1.15",
						},
					},
					"go_file": {
						{
							Value: "D:/渗透/go_shellcode_xor",
						},
					},
					"go_package": {
						{
							Value: "main",
						},
					},
					"go_package_function": {
						{
							Value:  "init",
							Label:  "main",
							Size:   342,
							Offset: 4639616,
						},
						{
							Value:  "main",
							Label:  "main",
							Size:   800,
							Offset: 4638816,
						},
					},
				},
			},
		},
	})
}

func TestGoDll(t *testing.T) {
	baseRunTest(t, "d3b1893d87dfd1f479dbfc460a68c3cb229bb2724fc51ed8bee00fd69c181ac7",
		"Malicious golang Windows 32DLL.",
		&plugin.TestJobResult{
			Status: "completed",
			Events: []plugin.TestJobEvent{
				{
					Features: map[string][]plugin.TestBinaryEntityFeature{
						"go_build_id": {
							{
								Value: "xhMUa-qNNwTDT3GYopIb/HKtvMqyMp4qH6Vajrskl/ZXqanGwJ3k9J59h_0q28/gf1702ff4LYu97S4-xt5",
							},
						},
						"go_compiler_timestamp": {
							{
								Value: "2020-10-14T19:10:41Z",
							},
						},
						"go_compiler_version": {
							{
								Value: "go1.15.3",
							},
						},
						"go_file": {
							{
								Value: "G:/GoProject/Reflective-HackBrowserData/x32/cmd",
							},
							{
								Value: "G:/GoProject/Reflective-HackBrowserData/x32/core",
							},
							{
								Value: "G:/GoProject/Reflective-HackBrowserData/x32/core/data",
							},
							{
								Value: "G:/GoProject/Reflective-HackBrowserData/x32/core/decrypt",
							},
							{
								Value: "G:/GoProject/Reflective-HackBrowserData/x32/log",
							},
							{
								Value: "G:/GoProject/Reflective-HackBrowserData/x32/utils",
							},
						},
						"go_package": {
							{
								Value: "hack-browser-data/cmd",
							},
							{
								Value: "hack-browser-data/core",
							},
							{
								Value: "hack-browser-data/core/data",
							},
							{
								Value: "hack-browser-data/core/decrypt",
							},
							{
								Value: "hack-browser-data/log",
							},
							{
								Value: "hack-browser-data/utils",
							},
							{
								Value: "main",
							},
						},
						"go_package_function": {
							{
								Value:  "ChromePass",
								Label:  "hack-browser-data/core/decrypt",
								Size:   224,
								Offset: 1704270832,
							},
							{
								Value:  "Compress",
								Label:  "hack-browser-data/utils",
								Size:   1392,
								Offset: 1703972960,
							},
							{
								Value:  "DPApi",
								Label:  "hack-browser-data/core/decrypt",
								Size:   880,
								Offset: 1704271632,
							},
							{
								Value:  "Execute",
								Label:  "hack-browser-data/cmd",
								Size:   2368,
								Offset: 1704947024,
							},
							{
								Value:  "FormatFileName",
								Label:  "hack-browser-data/utils",
								Size:   432,
								Offset: 1703972352,
							},
							{
								Value:  "InitLog",
								Label:  "hack-browser-data/log",
								Size:   304,
								Offset: 1703970320,
							},
							{
								Value:  "ListBrowser",
								Label:  "hack-browser-data/core",
								Size:   288,
								Offset: 1704498448,
							},
							{
								Value:  "MakeDir",
								Label:  "hack-browser-data/utils",
								Size:   176,
								Offset: 1703972784,
							},
							{
								Value:  "NewASN1PBE",
								Label:  "hack-browser-data/core/decrypt",
								Size:   672,
								Offset: 1704266784,
							},
							{
								Value:  "NewBookmarks",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704454816,
							},
							{
								Value:  "NewCCards",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704476176,
							},
							{
								Value:  "NewCPasswords",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704470464,
							},
							{
								Value:  "NewChromium",
								Label:  "hack-browser-data/core",
								Size:   272,
								Offset: 1704490192,
							},
							{
								Value:  "NewCookies",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704458896,
							},
							{
								Value:  "NewDownloads",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704466432,
							},
							{
								Value:  "NewFPasswords",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704470304,
							},
							{
								Value:  "NewFirefox",
								Label:  "hack-browser-data/core",
								Size:   224,
								Offset: 1704491936,
							},
							{
								Value:  "NewHistoryData",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704463040,
							},
							{
								Value:  "PaddingZero",
								Label:  "hack-browser-data/core/decrypt",
								Size:   192,
								Offset: 1704270464,
							},
							{
								Value:  "PickBrowser",
								Label:  "hack-browser-data/core",
								Size:   1120,
								Offset: 1704494752,
							},
							{
								Value:  "PickCustomBrowser",
								Label:  "hack-browser-data/core",
								Size:   1200,
								Offset: 1704495872,
							},
							{
								Value:  "TimeEpochFormat",
								Label:  "hack-browser-data/utils",
								Size:   384,
								Offset: 1703971968,
							},
							{
								Value:  "TimeStampFormat",
								Label:  "hack-browser-data/utils",
								Size:   400,
								Offset: 1703971568,
							},
							{
								Value:  "_cgoexpwrap_31f3981b8986_run",
								Label:  "main",
								Size:   32,
								Offset: 1704951456,
							},
							{
								Value:  "aes128CBCDecrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   352,
								Offset: 1704269712,
							},
							{
								Value:  "aesGCMDecrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   432,
								Offset: 1704271056,
							},
							{
								Value:  "checkKeyPath",
								Label:  "hack-browser-data/core",
								Size:   256,
								Offset: 1704497776,
							},
							{
								Value:  "copyToLocalPath",
								Label:  "hack-browser-data/core/data",
								Size:   592,
								Offset: 1704483168,
							},
							{
								Value:  "des3Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   400,
								Offset: 1704270064,
							},
							{
								Value:  "getBookmarkChildren",
								Label:  "hack-browser-data/core/data",
								Size:   1472,
								Offset: 1704455360,
							},
							{
								Value:  "getFirefoxDecryptKey",
								Label:  "hack-browser-data/core/data",
								Size:   2432,
								Offset: 1704478256,
							},
							{
								Value:  "getFirefoxLoginData",
								Label:  "hack-browser-data/core/data",
								Size:   1488,
								Offset: 1704480688,
							},
							{
								Value:  "getItemPath",
								Label:  "hack-browser-data/core",
								Size:   384,
								Offset: 1704497072,
							},
							{
								Value:  "getKeyPath",
								Label:  "hack-browser-data/core",
								Size:   320,
								Offset: 1704497456,
							},
							{
								Value:  "getParentDirectory",
								Label:  "hack-browser-data/core",
								Size:   416,
								Offset: 1704498032,
							},
							{
								Value:  "init",
								Label:  "hack-browser-data/core",
								Size:   6224,
								Offset: 1704499488,
							},
							{
								Value:  "init",
								Label:  "hack-browser-data/core/decrypt",
								Size:   320,
								Offset: 1704272512,
							},
							{
								Value:  "init",
								Label:  "hack-browser-data/log",
								Size:   192,
								Offset: 1703971264,
							},
							{
								Value:  "main",
								Label:  "main",
								Size:   32,
								Offset: 1704951488,
							},
							{
								Value:  "writeToCsv",
								Label:  "hack-browser-data/core/data",
								Size:   432,
								Offset: 1704452704,
							},
							{
								Value:  "writeToJson",
								Label:  "hack-browser-data/core/data",
								Size:   496,
								Offset: 1704449120,
							},
						},
						"go_package_method": {
							{
								Value:  "ChromeParse",
								Label:  "hack-browser-data/core/data",
								Size:   432,
								Offset: 1704454928,
							},
							{
								Value:  "ChromeParse",
								Label:  "hack-browser-data/core/data",
								Size:   2000,
								Offset: 1704459008,
							},
							{
								Value:  "ChromeParse",
								Label:  "hack-browser-data/core/data",
								Size:   1120,
								Offset: 1704463152,
							},
							{
								Value:  "ChromeParse",
								Label:  "hack-browser-data/core/data",
								Size:   1312,
								Offset: 1704466544,
							},
							{
								Value:  "ChromeParse",
								Label:  "hack-browser-data/core/data",
								Size:   1696,
								Offset: 1704470576,
							},
							{
								Value:  "ChromeParse",
								Label:  "hack-browser-data/core/data",
								Size:   1456,
								Offset: 1704476336,
							},
							{
								Value:  "CopyDB",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704458336,
							},
							{
								Value:  "CopyDB",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704462576,
							},
							{
								Value:  "CopyDB",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704465872,
							},
							{
								Value:  "CopyDB",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704469840,
							},
							{
								Value:  "CopyDB",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704475328,
							},
							{
								Value:  "CopyDB",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704477792,
							},
							{
								Value:  "Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   1728,
								Offset: 1704267456,
							},
							{
								Value:  "Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   528,
								Offset: 1704269184,
							},
							{
								Value:  "Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   176,
								Offset: 1704270656,
							},
							{
								Value:  "Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   240,
								Offset: 1704272832,
							},
							{
								Value:  "Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   272,
								Offset: 1704273072,
							},
							{
								Value:  "Decrypt",
								Label:  "hack-browser-data/core/decrypt",
								Size:   240,
								Offset: 1704273760,
							},
							{
								Value:  "Equal",
								Label:  "hack-browser-data/core/decrypt",
								Size:   112,
								Offset: 1704273344,
							},
							{
								Value:  "Equal",
								Label:  "hack-browser-data/core/decrypt",
								Size:   112,
								Offset: 1704273552,
							},
							{
								Value:  "Equal",
								Label:  "hack-browser-data/core/decrypt",
								Size:   128,
								Offset: 1704274000,
							},
							{
								Value:  "Equal",
								Label:  "hack-browser-data/core/decrypt",
								Size:   112,
								Offset: 1704274224,
							},
							{
								Value:  "FirefoxParse",
								Label:  "hack-browser-data/core/data",
								Size:   1504,
								Offset: 1704456832,
							},
							{
								Value:  "FirefoxParse",
								Label:  "hack-browser-data/core/data",
								Size:   1568,
								Offset: 1704461008,
							},
							{
								Value:  "FirefoxParse",
								Label:  "hack-browser-data/core/data",
								Size:   1600,
								Offset: 1704464272,
							},
							{
								Value:  "FirefoxParse",
								Label:  "hack-browser-data/core/data",
								Size:   1984,
								Offset: 1704467856,
							},
							{
								Value:  "FirefoxParse",
								Label:  "hack-browser-data/core/data",
								Size:   3056,
								Offset: 1704472272,
							},
							{
								Value:  "FirefoxParse",
								Label:  "hack-browser-data/core/data",
								Size:   48,
								Offset: 1704476288,
							},
							{
								Value:  "GetAllItems",
								Label:  "hack-browser-data/core",
								Size:   864,
								Offset: 1704490576,
							},
							{
								Value:  "GetAllItems",
								Label:  "hack-browser-data/core",
								Size:   1280,
								Offset: 1704492160,
							},
							{
								Value:  "GetItem",
								Label:  "hack-browser-data/core",
								Size:   496,
								Offset: 1704491440,
							},
							{
								Value:  "GetItem",
								Label:  "hack-browser-data/core",
								Size:   1152,
								Offset: 1704493440,
							},
							{
								Value:  "GetName",
								Label:  "hack-browser-data/core",
								Size:   48,
								Offset: 1704490464,
							},
							{
								Value:  "GetName",
								Label:  "hack-browser-data/core",
								Size:   48,
								Offset: 1704494592,
							},
							{
								Value:  "GetSecretKey",
								Label:  "hack-browser-data/core",
								Size:   64,
								Offset: 1704490512,
							},
							{
								Value:  "GetSecretKey",
								Label:  "hack-browser-data/core",
								Size:   64,
								Offset: 1704494640,
							},
							{
								Value:  "InitSecretKey",
								Label:  "hack-browser-data/core",
								Size:   48,
								Offset: 1704494704,
							},
							{
								Value:  "InitSecretKey",
								Label:  "hack-browser-data/core",
								Size:   752,
								Offset: 1704498736,
							},
							{
								Value:  "Len",
								Label:  "hack-browser-data/core/data",
								Size:   48,
								Offset: 1704482176,
							},
							{
								Value:  "Len",
								Label:  "hack-browser-data/core/data",
								Size:   48,
								Offset: 1704482688,
							},
							{
								Value:  "Len",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704487280,
							},
							{
								Value:  "Len",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704487904,
							},
							{
								Value:  "Less",
								Label:  "hack-browser-data/core/data",
								Size:   176,
								Offset: 1704482224,
							},
							{
								Value:  "Less",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704482736,
							},
							{
								Value:  "Less",
								Label:  "hack-browser-data/core/data",
								Size:   208,
								Offset: 1704487376,
							},
							{
								Value:  "Less",
								Label:  "hack-browser-data/core/data",
								Size:   224,
								Offset: 1704488000,
							},
							{
								Value:  "OutPut",
								Label:  "hack-browser-data/core/data",
								Size:   368,
								Offset: 1704458528,
							},
							{
								Value:  "OutPut",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704462768,
							},
							{
								Value:  "OutPut",
								Label:  "hack-browser-data/core/data",
								Size:   368,
								Offset: 1704466064,
							},
							{
								Value:  "OutPut",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704470032,
							},
							{
								Value:  "OutPut",
								Label:  "hack-browser-data/core/data",
								Size:   304,
								Offset: 1704475872,
							},
							{
								Value:  "OutPut",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704477984,
							},
							{
								Value:  "Release",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704458432,
							},
							{
								Value:  "Release",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704462672,
							},
							{
								Value:  "Release",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704465968,
							},
							{
								Value:  "Release",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704469936,
							},
							{
								Value:  "Release",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704475600,
							},
							{
								Value:  "Release",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704477888,
							},
							{
								Value:  "String",
								Label:  "hack-browser-data/core/decrypt",
								Size:   96,
								Offset: 1704273456,
							},
							{
								Value:  "String",
								Label:  "hack-browser-data/core/decrypt",
								Size:   96,
								Offset: 1704273664,
							},
							{
								Value:  "String",
								Label:  "hack-browser-data/core/decrypt",
								Size:   96,
								Offset: 1704274128,
							},
							{
								Value:  "String",
								Label:  "hack-browser-data/core/decrypt",
								Size:   96,
								Offset: 1704274336,
							},
							{
								Value:  "String",
								Label:  "hack-browser-data/log",
								Size:   96,
								Offset: 1703970224,
							},
							{
								Value:  "String",
								Label:  "hack-browser-data/log",
								Size:   112,
								Offset: 1703971456,
							},
							{
								Value:  "Swap",
								Label:  "hack-browser-data/core/data",
								Size:   288,
								Offset: 1704482400,
							},
							{
								Value:  "Swap",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704482896,
							},
							{
								Value:  "Swap",
								Label:  "hack-browser-data/core/data",
								Size:   320,
								Offset: 1704487584,
							},
							{
								Value:  "Swap",
								Label:  "hack-browser-data/core/data",
								Size:   336,
								Offset: 1704488224,
							},
							{
								Value:  "ToByteArray",
								Label:  "hack-browser-data/core/decrypt",
								Size:   144,
								Offset: 1704271488,
							},
							{
								Value:  "doLog",
								Label:  "hack-browser-data/log",
								Size:   272,
								Offset: 1703970624,
							},
							{
								Value:  "doLogf",
								Label:  "hack-browser-data/log",
								Size:   368,
								Offset: 1703970896,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/cmd",
								Size:   1920,
								Offset: 1704949392,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704483760,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704483872,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   64,
								Offset: 1704483968,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704484032,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   112,
								Offset: 1704484176,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704484288,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704484592,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704484896,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704485200,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   96,
								Offset: 1704485504,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704485600,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704485904,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704486208,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704486512,
							},
							{
								Value:  "func1",
								Label:  "hack-browser-data/core/data",
								Size:   144,
								Offset: 1704486816,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704484432,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704484736,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704485040,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704485344,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704485744,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704486048,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704486352,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704486656,
							},
							{
								Value:  "func2",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704486960,
							},
							{
								Value:  "func3",
								Label:  "hack-browser-data/core/data",
								Size:   160,
								Offset: 1704487120,
							},
							{
								Value:  "outPutConsole",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704453136,
							},
							{
								Value:  "outPutConsole",
								Label:  "hack-browser-data/core/data",
								Size:   336,
								Offset: 1704453408,
							},
							{
								Value:  "outPutConsole",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704453744,
							},
							{
								Value:  "outPutConsole",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704454016,
							},
							{
								Value:  "outPutConsole",
								Label:  "hack-browser-data/core/data",
								Size:   272,
								Offset: 1704454288,
							},
							{
								Value:  "outPutConsole",
								Label:  "hack-browser-data/core/data",
								Size:   256,
								Offset: 1704454560,
							},
							{
								Value:  "outPutCsv",
								Label:  "hack-browser-data/core/data",
								Size:   416,
								Offset: 1704449616,
							},
							{
								Value:  "outPutCsv",
								Label:  "hack-browser-data/core/data",
								Size:   416,
								Offset: 1704450032,
							},
							{
								Value:  "outPutCsv",
								Label:  "hack-browser-data/core/data",
								Size:   416,
								Offset: 1704450448,
							},
							{
								Value:  "outPutCsv",
								Label:  "hack-browser-data/core/data",
								Size:   416,
								Offset: 1704450864,
							},
							{
								Value:  "outPutCsv",
								Label:  "hack-browser-data/core/data",
								Size:   704,
								Offset: 1704451280,
							},
							{
								Value:  "outPutCsv",
								Label:  "hack-browser-data/core/data",
								Size:   720,
								Offset: 1704451984,
							},
							{
								Value:  "outPutJson",
								Label:  "hack-browser-data/core/data",
								Size:   512,
								Offset: 1704446464,
							},
							{
								Value:  "outPutJson",
								Label:  "hack-browser-data/core/data",
								Size:   512,
								Offset: 1704446976,
							},
							{
								Value:  "outPutJson",
								Label:  "hack-browser-data/core/data",
								Size:   416,
								Offset: 1704447488,
							},
							{
								Value:  "outPutJson",
								Label:  "hack-browser-data/core/data",
								Size:   416,
								Offset: 1704447904,
							},
							{
								Value:  "outPutJson",
								Label:  "hack-browser-data/core/data",
								Size:   400,
								Offset: 1704448320,
							},
							{
								Value:  "outPutJson",
								Label:  "hack-browser-data/core/data",
								Size:   400,
								Offset: 1704448720,
							},
						},
						"go_type": {
							{
								Value:  "*core.Chromium",
								Label:  "ptr",
								Offset: 1706065120,
							},
							{
								Value:  "*core.Firefox",
								Label:  "ptr",
								Offset: 1706065280,
							},
							{
								Value:  "*data.bookmarks",
								Label:  "ptr",
								Offset: 1706095968,
							},
							{
								Value:  "*data.cookies",
								Label:  "ptr",
								Offset: 1706096160,
							},
							{
								Value:  "*data.creditCards",
								Label:  "ptr",
								Offset: 1706096352,
							},
							{
								Value:  "*data.downloads",
								Label:  "ptr",
								Offset: 1706111872,
							},
							{
								Value:  "*data.historyData",
								Label:  "ptr",
								Offset: 1706096544,
							},
							{
								Value:  "*data.passwords",
								Label:  "ptr",
								Offset: 1706112128,
							},
							{
								Value:  "*decrypt.LoginPBE",
								Label:  "ptr",
								Offset: 1706028224,
							},
							{
								Value:  "*decrypt.LoginSequence",
								Label:  "ptr",
								Offset: 1705995520,
							},
							{
								Value:  "*decrypt.MetaPBE",
								Label:  "ptr",
								Offset: 1705968192,
							},
							{
								Value:  "*decrypt.NssPBE",
								Label:  "ptr",
								Offset: 1705968288,
							},
							{
								Value:  "*decrypt.dataBlob",
								Label:  "ptr",
								Offset: 1705968384,
							},
							{
								Value:  "*log.Level",
								Label:  "ptr",
								Offset: 1705968480,
							},
							{
								Value:  "*log.Logger",
								Label:  "ptr",
								Offset: 1706052640,
							},
							{
								Value:  "core.Browser",
								Label:  "interface",
								Offset: 1706040896,
							},
							{
								Value:  "core.Chromium",
								Label:  "struct",
								Offset: 1706059296,
							},
							{
								Value:  "core.Firefox",
								Label:  "struct",
								Offset: 1706033952,
							},
							{
								Value:  "data.Item",
								Label:  "interface",
								Offset: 1706041024,
							},
							{
								Value:  "data.bookmarks",
								Label:  "struct",
								Offset: 1706007168,
							},
							{
								Value:  "data.cookie",
								Label:  "struct",
								Offset: 1706104128,
							},
							{
								Value:  "data.cookies",
								Label:  "struct",
								Offset: 1706007264,
							},
							{
								Value:  "data.creditCards",
								Label:  "struct",
								Offset: 1706007360,
							},
							{
								Value:  "data.downloads",
								Label:  "struct",
								Offset: 1706071648,
							},
							{
								Value:  "data.historyData",
								Label:  "struct",
								Offset: 1706007456,
							},
							{
								Value:  "data.loginData",
								Label:  "struct",
								Offset: 1706071808,
							},
							{
								Value:  "data.passwords",
								Label:  "struct",
								Offset: 1706080832,
							},
							{
								Value:  "decrypt.ASN1PBE",
								Label:  "interface",
								Offset: 1705977504,
							},
							{
								Value:  "decrypt.dataBlob",
								Label:  "struct",
								Offset: 1706008128,
							},
							{
								Value:  "log.Logger",
								Label:  "struct",
								Offset: 1706008224,
							},
							{
								Value:  "struct { mainFile string; newItem func(string, string) data.Item }",
								Label:  "struct",
								Offset: 1705985664,
							},
							{
								Value:  "struct { mainFile string; subFile string; newItem func(string, string) data.Item }",
								Label:  "struct",
								Offset: 1706002432,
							},
						},
						"go_type_method": {
							{
								Value: "ChromeParse",
								Label: "*data.bookmarks",
							},
							{
								Value: "ChromeParse",
								Label: "*data.cookies",
							},
							{
								Value: "ChromeParse",
								Label: "*data.creditCards",
							},
							{
								Value: "ChromeParse",
								Label: "*data.downloads",
							},
							{
								Value: "ChromeParse",
								Label: "*data.historyData",
							},
							{
								Value: "ChromeParse",
								Label: "*data.passwords",
							},
							{
								Value: "ChromeParse",
								Label: "data.Item",
							},
							{
								Value: "CopyDB",
								Label: "*data.bookmarks",
							},
							{
								Value: "CopyDB",
								Label: "*data.cookies",
							},
							{
								Value: "CopyDB",
								Label: "*data.creditCards",
							},
							{
								Value: "CopyDB",
								Label: "*data.downloads",
							},
							{
								Value: "CopyDB",
								Label: "*data.historyData",
							},
							{
								Value: "CopyDB",
								Label: "*data.passwords",
							},
							{
								Value: "CopyDB",
								Label: "data.Item",
							},
							{
								Value: "Decrypt",
								Label: "*decrypt.LoginPBE",
							},
							{
								Value: "Decrypt",
								Label: "*decrypt.MetaPBE",
							},
							{
								Value: "Decrypt",
								Label: "*decrypt.NssPBE",
							},
							{
								Value: "Decrypt",
								Label: "decrypt.ASN1PBE",
							},
							{
								Value: "Equal",
								Label: "*decrypt.LoginPBE",
							},
							{
								Value: "Equal",
								Label: "*decrypt.LoginSequence",
							},
							{
								Value: "FirefoxParse",
								Label: "*data.bookmarks",
							},
							{
								Value: "FirefoxParse",
								Label: "*data.cookies",
							},
							{
								Value: "FirefoxParse",
								Label: "*data.creditCards",
							},
							{
								Value: "FirefoxParse",
								Label: "*data.downloads",
							},
							{
								Value: "FirefoxParse",
								Label: "*data.historyData",
							},
							{
								Value: "FirefoxParse",
								Label: "*data.passwords",
							},
							{
								Value: "FirefoxParse",
								Label: "data.Item",
							},
							{
								Value: "GetAllItems",
								Label: "*core.Chromium",
							},
							{
								Value: "GetAllItems",
								Label: "*core.Firefox",
							},
							{
								Value: "GetAllItems",
								Label: "core.Browser",
							},
							{
								Value: "GetItem",
								Label: "*core.Chromium",
							},
							{
								Value: "GetItem",
								Label: "*core.Firefox",
							},
							{
								Value: "GetItem",
								Label: "core.Browser",
							},
							{
								Value: "GetName",
								Label: "*core.Chromium",
							},
							{
								Value: "GetName",
								Label: "*core.Firefox",
							},
							{
								Value: "GetName",
								Label: "core.Browser",
							},
							{
								Value: "GetSecretKey",
								Label: "*core.Chromium",
							},
							{
								Value: "GetSecretKey",
								Label: "*core.Firefox",
							},
							{
								Value: "GetSecretKey",
								Label: "core.Browser",
							},
							{
								Value: "InitSecretKey",
								Label: "*core.Chromium",
							},
							{
								Value: "InitSecretKey",
								Label: "*core.Firefox",
							},
							{
								Value: "InitSecretKey",
								Label: "core.Browser",
							},
							{
								Value: "Len",
								Label: "*data.downloads",
							},
							{
								Value: "Len",
								Label: "*data.passwords",
							},
							{
								Value: "Len",
								Label: "data.downloads",
							},
							{
								Value: "Len",
								Label: "data.passwords",
							},
							{
								Value: "Less",
								Label: "*data.downloads",
							},
							{
								Value: "Less",
								Label: "*data.passwords",
							},
							{
								Value: "Less",
								Label: "data.downloads",
							},
							{
								Value: "Less",
								Label: "data.passwords",
							},
							{
								Value: "OutPut",
								Label: "*data.bookmarks",
							},
							{
								Value: "OutPut",
								Label: "*data.cookies",
							},
							{
								Value: "OutPut",
								Label: "*data.creditCards",
							},
							{
								Value: "OutPut",
								Label: "*data.downloads",
							},
							{
								Value: "OutPut",
								Label: "*data.historyData",
							},
							{
								Value: "OutPut",
								Label: "*data.passwords",
							},
							{
								Value: "OutPut",
								Label: "data.Item",
							},
							{
								Value: "Release",
								Label: "*data.bookmarks",
							},
							{
								Value: "Release",
								Label: "*data.cookies",
							},
							{
								Value: "Release",
								Label: "*data.creditCards",
							},
							{
								Value: "Release",
								Label: "*data.downloads",
							},
							{
								Value: "Release",
								Label: "*data.historyData",
							},
							{
								Value: "Release",
								Label: "*data.passwords",
							},
							{
								Value: "Release",
								Label: "data.Item",
							},
							{
								Value: "String",
								Label: "*decrypt.LoginPBE",
							},
							{
								Value: "String",
								Label: "*decrypt.LoginSequence",
							},
							{
								Value: "String",
								Label: "*log.Level",
							},
							{
								Value: "Swap",
								Label: "*data.downloads",
							},
							{
								Value: "Swap",
								Label: "*data.passwords",
							},
							{
								Value: "Swap",
								Label: "data.downloads",
							},
							{
								Value: "Swap",
								Label: "data.passwords",
							},
							{
								Value: "ToByteArray",
								Label: "*decrypt.dataBlob",
							},
							{
								Value: "doLog",
								Label: "*log.Logger",
							},
							{
								Value: "doLogf",
								Label: "*log.Logger",
							},
							{
								Value: "outPutConsole",
								Label: "*data.bookmarks",
							},
							{
								Value: "outPutConsole",
								Label: "*data.cookies",
							},
							{
								Value: "outPutConsole",
								Label: "*data.creditCards",
							},
							{
								Value: "outPutConsole",
								Label: "*data.downloads",
							},
							{
								Value: "outPutConsole",
								Label: "*data.historyData",
							},
							{
								Value: "outPutConsole",
								Label: "*data.passwords",
							},
							{
								Value: "outPutCsv",
								Label: "*data.bookmarks",
							},
							{
								Value: "outPutCsv",
								Label: "*data.cookies",
							},
							{
								Value: "outPutCsv",
								Label: "*data.creditCards",
							},
							{
								Value: "outPutCsv",
								Label: "*data.downloads",
							},
							{
								Value: "outPutCsv",
								Label: "*data.historyData",
							},
							{
								Value: "outPutCsv",
								Label: "*data.passwords",
							},
							{
								Value: "outPutJson",
								Label: "*data.bookmarks",
							},
							{
								Value: "outPutJson",
								Label: "*data.cookies",
							},
							{
								Value: "outPutJson",
								Label: "*data.creditCards",
							},
							{
								Value: "outPutJson",
								Label: "*data.downloads",
							},
							{
								Value: "outPutJson",
								Label: "*data.historyData",
							},
							{
								Value: "outPutJson",
								Label: "*data.passwords",
							},
							{
								Value: "setFlags",
								Label: "*log.Logger",
							},
							{
								Value: "setLevel",
								Label: "*log.Logger",
							},
						},
						"go_vendor_package": {
							{
								Value: "github.com/cpuguy83/go-md2man/v2/md2man",
							},
							{
								Value: "github.com/jszwec/csvutil",
							},
							{
								Value: "github.com/mattn/go-sqlite3",
							},
							{
								Value: "github.com/russross/blackfriday/v2",
							},
							{
								Value: "github.com/shurcooL/sanitized_anchor_name",
							},
							{
								Value: "github.com/tidwall/gjson",
							},
							{
								Value: "github.com/tidwall/match",
							},
							{
								Value: "github.com/tidwall/pretty",
							},
							{
								Value: "github.com/urfave/cli/v2",
							},
							{
								Value: "golang.org/x/crypto/pbkdf2",
							},
						},
					},
				},
			},
		})
}

func TestGoElf(t *testing.T) {
	baseRunTest(t, "5059d67cd24eb4b0b4a174a072ceac6a47e14c3302da2c6581f81c39d8a076c6",
		"Malicious golang ELF32, malware family REDSONJA.",
		&plugin.TestJobResult{
			Status: "completed",
			Events: []plugin.TestJobEvent{
				{
					Features: map[string][]plugin.TestBinaryEntityFeature{
						"go_build_id": {
							{
								Value: "9d680556d0b7d3c4b367b7886b4180a13548557b",
							},
						},
						"go_file": {
							{
								Value: "/app",
							},
						},
						"go_package": {
							{
								Value: "main",
							},
						},
						"go_package_function": {
							{
								Value:  "DownloadFile",
								Label:  "main",
								Size:   1152,
								Offset: 7280192,
							},
							{
								Value:  "Hosts",
								Label:  "main",
								Size:   752,
								Offset: 7310976,
							},
							{
								Value:  "RC4",
								Label:  "main",
								Size:   432,
								Offset: 7281824,
							},
							{
								Value:  "RandStringRunes",
								Label:  "main",
								Size:   256,
								Offset: 7310720,
							},
							{
								Value:  "addResult",
								Label:  "main",
								Size:   192,
								Offset: 7285760,
							},
							{
								Value:  "backconnect",
								Label:  "main",
								Size:   80,
								Offset: 7300736,
							},
							{
								Value:  "checkHealth",
								Label:  "main",
								Size:   1056,
								Offset: 7275808,
							},
							{
								Value:  "connectForSocks",
								Label:  "main",
								Size:   992,
								Offset: 7286400,
							},
							{
								Value:  "contains",
								Label:  "main",
								Size:   192,
								Offset: 7312000,
							},
							{
								Value:  "doRequestWithTooManyOpenFiles",
								Label:  "main",
								Size:   1888,
								Offset: 7282256,
							},
							{
								Value:  "doTask",
								Label:  "main",
								Size:   992,
								Offset: 7253840,
							},
							{
								Value:  "downloadAndExecute",
								Label:  "main",
								Size:   80,
								Offset: 7309200,
							},
							{
								Value:  "encStruct",
								Label:  "main",
								Size:   192,
								Offset: 7280000,
							},
							{
								Value:  "execTask",
								Label:  "main",
								Size:   80,
								Offset: 7290096,
							},
							{
								Value:  "execTaskOut",
								Label:  "main",
								Size:   80,
								Offset: 7290176,
							},
							{
								Value:  "getOrCreateListForTaskResult",
								Label:  "main",
								Size:   448,
								Offset: 7285952,
							},
							{
								Value:  "getOrCreateRateCounterForTask",
								Label:  "main",
								Size:   256,
								Offset: 7254832,
							},
							{
								Value:  "getOrCreateUuid",
								Label:  "main",
								Size:   320,
								Offset: 7287520,
							},
							{
								Value:  "getTargets",
								Label:  "main",
								Size:   4432,
								Offset: 7267456,
							},
							{
								Value:  "getTask",
								Label:  "main",
								Size:   1600,
								Offset: 7265856,
							},
							{
								Value:  "getWriteableDir",
								Label:  "main",
								Size:   512,
								Offset: 7263408,
							},
							{
								Value:  "hash_file_md5",
								Label:  "main",
								Size:   592,
								Offset: 7312192,
							},
							{
								Value:  "healthChecker",
								Label:  "main",
								Size:   336,
								Offset: 7263072,
							},
							{
								Value:  "inc",
								Label:  "main",
								Size:   80,
								Offset: 7311728,
							},
							{
								Value:  "init",
								Label:  "main",
								Size:   624,
								Offset: 7320064,
							},
							{
								Value:  "main",
								Label:  "main",
								Size:   4784,
								Offset: 7258288,
							},
							{
								Value:  "makeClient",
								Label:  "main",
								Size:   480,
								Offset: 7281344,
							},
							{
								Value:  "masscan",
								Label:  "main",
								Size:   3248,
								Offset: 7297408,
							},
							{
								Value:  "move",
								Label:  "main",
								Size:   368,
								Offset: 7287840,
							},
							{
								Value:  "randIntRange",
								Label:  "main",
								Size:   96,
								Offset: 7311808,
							},
							{
								Value:  "redisBrute",
								Label:  "main",
								Size:   1440,
								Offset: 7309280,
							},
							{
								Value:  "request",
								Label:  "main",
								Size:   5024,
								Offset: 7300816,
							},
							{
								Value:  "resultSender",
								Label:  "main",
								Size:   1616,
								Offset: 7284144,
							},
							{
								Value:  "runTask",
								Label:  "main",
								Size:   1264,
								Offset: 7288320,
							},
							{
								Value:  "runTaskWithHttp",
								Label:  "main",
								Size:   1280,
								Offset: 7290256,
							},
							{
								Value:  "runTaskWithScan",
								Label:  "main",
								Size:   832,
								Offset: 7292048,
							},
							{
								Value:  "runcmd",
								Label:  "main",
								Size:   1296,
								Offset: 7255088,
							},
							{
								Value:  "sendResult",
								Label:  "main",
								Size:   2272,
								Offset: 7271888,
							},
							{
								Value:  "sendSocks",
								Label:  "main",
								Size:   1648,
								Offset: 7274160,
							},
							{
								Value:  "setExecOutput",
								Label:  "main",
								Size:   1568,
								Offset: 7278432,
							},
							{
								Value:  "setLog",
								Label:  "main",
								Size:   1568,
								Offset: 7276864,
							},
							{
								Value:  "setUuid",
								Label:  "main",
								Size:   128,
								Offset: 7287392,
							},
							{
								Value:  "socks",
								Label:  "main",
								Size:   80,
								Offset: 7300656,
							},
							{
								Value:  "startCmd",
								Label:  "main",
								Size:   1152,
								Offset: 7256384,
							},
							{
								Value:  "startSocks",
								Label:  "main",
								Size:   1936,
								Offset: 7263920,
							},
							{
								Value:  "syncCmd",
								Label:  "main",
								Size:   112,
								Offset: 7288208,
							},
							{
								Value:  "taskScan",
								Label:  "main",
								Size:   480,
								Offset: 7296928,
							},
							{
								Value:  "taskWithHttpWorker",
								Label:  "main",
								Size:   512,
								Offset: 7291536,
							},
							{
								Value:  "taskWithScanWorker",
								Label:  "main",
								Size:   528,
								Offset: 7292880,
							},
							{
								Value:  "taskWorker",
								Label:  "main",
								Size:   512,
								Offset: 7289584,
							},
							{
								Value:  "tcpTask",
								Label:  "main",
								Size:   3360,
								Offset: 7305840,
							},
							{
								Value:  "updateTask",
								Label:  "main",
								Size:   3520,
								Offset: 7293408,
							},
							{
								Value:  "writable",
								Label:  "main",
								Size:   96,
								Offset: 7311904,
							},
						},
						"go_package_method": {
							{
								Value:  "0",
								Label:  "main",
								Size:   752,
								Offset: 7257536,
							},
							{
								Value:  "1",
								Label:  "main",
								Size:   240,
								Offset: 7315184,
							},
							{
								Value:  "1",
								Label:  "main",
								Size:   80,
								Offset: 7318960,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   96,
								Offset: 7312784,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   304,
								Offset: 7312880,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   912,
								Offset: 7313184,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   176,
								Offset: 7314096,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   912,
								Offset: 7314272,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   1728,
								Offset: 7315424,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   80,
								Offset: 7317152,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   832,
								Offset: 7317232,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   896,
								Offset: 7318064,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   1024,
								Offset: 7319040,
							},
						},
						"go_type": {
							{
								Value:  "main.ExecOutput",
								Label:  "struct",
								Offset: 7779008,
							},
							{
								Value:  "main.Result",
								Label:  "struct",
								Offset: 7779168,
							},
							{
								Value:  "main.SetSocks",
								Label:  "struct",
								Offset: 7828224,
							},
							{
								Value:  "main.Specification",
								Label:  "struct",
								Offset: 7828416,
							},
							{
								Value:  "main.TargetsWrapper",
								Label:  "struct",
								Offset: 7779328,
							},
							{
								Value:  "main.Task",
								Label:  "struct",
								Offset: 7934688,
							},
							{
								Value:  "main.TaskPair",
								Label:  "struct",
								Offset: 7779488,
							},
							{
								Value:  "struct { F uintptr; R *net.Dialer }",
								Label:  "struct",
								Offset: 7746528,
							},
							{
								Value:  "struct { elem *uint8; chan *uint8; pc uintptr; kind uint16; receivedp *uint8; releasetime uint64 }",
								Label:  "struct",
								Offset: 7909664,
							},
							{
								Value:  "struct { tcase uint16; ncase uint16; pollorder *uint8; lockorder *uint8; scase [2]struct { elem *uint8; chan *uint8; pc uintptr; kind uint16; receivedp *uint8; releasetime uint64 }; lockorderarr [2]uint16; pollorderarr [2]uint16 }",
								Label:  "struct",
								Offset: 7928192,
							},
						},
						"go_vendor_package": {
							{
								Value: "github.com/armon/go-socks5",
							},
							{
								Value: "github.com/go-resty/resty",
							},
							{
								Value: "github.com/hashicorp/yamux",
							},
							{
								Value: "github.com/kardianos/osext",
							},
							{
								Value: "github.com/kelseyhightower/envconfig",
							},
							{
								Value: "github.com/nu7hatch/gouuid",
							},
							{
								Value: "github.com/op/go-logging",
							},
							{
								Value: "github.com/paulbellamy/ratecounter",
							},
							{
								Value: "github.com/peterbourgon/diskv",
							},
							{
								Value: "github.com/shirou/gopsutil/cpu",
							},
							{
								Value: "github.com/shirou/gopsutil/host",
							},
							{
								Value: "github.com/shirou/gopsutil/internal/common",
							},
							{
								Value: "github.com/shirou/gopsutil/mem",
							},
							{
								Value: "golang.org/x/net/publicsuffix",
							},
							{
								Value: "golang.org/x/sys/unix",
							},
							{
								Value: "vendor/golang_org/x/net/route.(*wireFormat).(vendor/golang_org/x/net/route",
							},
						},
					},
				},
			},
		})
}

func TestGoMacho(t *testing.T) {
	baseRunTest(t, "aaaac0ecd3db39d5ec25409e308a3a6679ca898617c8b9d17f73e17ffec24e85",
		"Malicious golang Mach-O.",
		&plugin.TestJobResult{
			Status: "completed",
			Events: []plugin.TestJobEvent{
				{
					Features: map[string][]plugin.TestBinaryEntityFeature{
						"go_build_id": {
							{
								Value: "e5UluFEoR-R3eIV9ElNE/aYCW0S1jxp_v3tP4n86g/IbJMBlYvAz5DFUB3S1LA/JzpLkFWLldbZBDD18sYI",
							},
						},
						"go_compiler_timestamp": {
							{
								Value: "2021-10-07T18:11:41Z",
							},
						},
						"go_compiler_version": {
							{
								Value: "go1.17.2",
							},
						},
						"go_file": {
							{
								Value: "/home/user/GoProjects/proxit/src/proxit.com/peer",
							},
							{
								Value: "/home/user/GoProjects/proxit/src/proxit.com/peer/config",
							},
							{
								Value: "/home/user/GoProjects/proxit/src/proxit.com/peer/peer",
							},
						},
						"go_package": {
							{
								Value: "main",
							},
							{
								Value: "proxit.com/peer/config",
							},
							{
								Value: "proxit.com/peer/peer",
							},
						},
						"go_package_function": {
							{
								Value:  "LoadCfg",
								Label:  "proxit.com/peer/config",
								Size:   864,
								Offset: 21614944,
							},
							{
								Value:  "NewPeer",
								Label:  "proxit.com/peer/peer",
								Size:   992,
								Offset: 21616096,
							},
							{
								Value:  "RealMain",
								Label:  "proxit.com/peer/peer",
								Size:   960,
								Offset: 21635872,
							},
							{
								Value:  "init",
								Label:  "proxit.com/peer/peer",
								Size:   160,
								Offset: 21637248,
							},
							{
								Value:  "main",
								Label:  "main",
								Size:   47,
								Offset: 21637920,
							},
						},
						"go_package_method": {
							{
								Value:  "Start",
								Label:  "proxit.com/peer/peer",
								Size:   6080,
								Offset: 21622528,
							},
							{
								Value:  "Start·dwrap·3",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21628800,
							},
							{
								Value:  "Start·dwrap·4",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21628704,
							},
							{
								Value:  "Start·dwrap·5",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21628608,
							},
							{
								Value:  "Stop",
								Label:  "proxit.com/peer/peer",
								Size:   768,
								Offset: 21635104,
							},
							{
								Value:  "bufferCopier",
								Label:  "proxit.com/peer/peer",
								Size:   1792,
								Offset: 21620096,
							},
							{
								Value:  "connectToCnc",
								Label:  "proxit.com/peer/peer",
								Size:   544,
								Offset: 21621888,
							},
							{
								Value:  "connectToDestination",
								Label:  "proxit.com/peer/peer",
								Size:   576,
								Offset: 21617760,
							},
							{
								Value:  "connectToProxyManager",
								Label:  "proxit.com/peer/peer",
								Size:   672,
								Offset: 21617088,
							},
							{
								Value:  "func1",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21622432,
							},
							{
								Value:  "func1",
								Label:  "proxit.com/peer/peer",
								Size:   416,
								Offset: 21636832,
							},
							{
								Value:  "func2",
								Label:  "proxit.com/peer/peer",
								Size:   32,
								Offset: 21637408,
							},
							{
								Value:  "getDestinationConnection",
								Label:  "proxit.com/peer/peer",
								Size:   2080,
								Offset: 21629984,
							},
							{
								Value:  "getDestinationConnection·dwrap·6",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21632064,
							},
							{
								Value:  "getProxyManagerConnection",
								Label:  "proxit.com/peer/peer",
								Size:   2848,
								Offset: 21632160,
							},
							{
								Value:  "getProxyManagerConnection·dwrap·7",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21635008,
							},
							{
								Value:  "heartbeatSender",
								Label:  "proxit.com/peer/peer",
								Size:   800,
								Offset: 21618752,
							},
							{
								Value:  "heartbeatSenderLoop",
								Label:  "proxit.com/peer/peer",
								Size:   416,
								Offset: 21618336,
							},
							{
								Value:  "logAndSendErrorToCnc",
								Label:  "proxit.com/peer/peer",
								Size:   1088,
								Offset: 21628896,
							},
							{
								Value:  "redirect",
								Label:  "proxit.com/peer/peer",
								Size:   352,
								Offset: 21619552,
							},
							{
								Value:  "redirect·dwrap·1",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21620000,
							},
							{
								Value:  "redirect·dwrap·2",
								Label:  "proxit.com/peer/peer",
								Size:   96,
								Offset: 21619904,
							},
						},
						"go_type": {
							{
								Value:  "*peer.Peer",
								Label:  "ptr",
								Offset: 22497824,
							},
							{
								Value:  "peer.ConnectionError",
								Label:  "struct",
								Offset: 22324608,
							},
							{
								Value:  "peer.ConnectionOrError",
								Label:  "struct",
								Offset: 22324800,
							},
							{
								Value:  "peer.NamedConnection",
								Label:  "struct",
								Offset: 22253216,
							},
							{
								Value:  "peer.Peer",
								Label:  "struct",
								Offset: 22507904,
							},
						},
						"go_type_method": {
							{
								Value: "Start",
								Label: "*peer.Peer",
							},
							{
								Value: "Stop",
								Label: "*peer.Peer",
							},
							{
								Value: "bufferCopier",
								Label: "*peer.Peer",
							},
							{
								Value: "connectToCnc",
								Label: "*peer.Peer",
							},
							{
								Value: "connectToDestination",
								Label: "*peer.Peer",
							},
							{
								Value: "connectToProxyManager",
								Label: "*peer.Peer",
							},
							{
								Value: "getDestinationConnection",
								Label: "*peer.Peer",
							},
							{
								Value: "getProxyManagerConnection",
								Label: "*peer.Peer",
							},
							{
								Value: "heartbeatSender",
								Label: "*peer.Peer",
							},
							{
								Value: "heartbeatSenderLoop",
								Label: "*peer.Peer",
							},
							{
								Value: "logAndSendErrorToCnc",
								Label: "*peer.Peer",
							},
							{
								Value: "redirect",
								Label: "*peer.Peer",
							},
						},
						"go_vendor_package": {
							{
								Value: "github.com/denisbrodbeck/machineid",
							},
							{
								Value: "github.com/distatus/battery",
							},
							{
								Value: "github.com/fsnotify/fsnotify",
							},
							{
								Value: "github.com/golang/protobuf/proto",
							},
							{
								Value: "github.com/golang/protobuf/ptypes",
							},
							{
								Value: "github.com/golang/protobuf/ptypes/any",
							},
							{
								Value: "github.com/golang/protobuf/ptypes/duration",
							},
							{
								Value: "github.com/golang/protobuf/ptypes/timestamp",
							},
							{
								Value: "github.com/hashicorp/hcl",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/ast",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/parser",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/scanner",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/strconv",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/token",
							},
							{
								Value: "github.com/hashicorp/hcl/json/parser",
							},
							{
								Value: "github.com/hashicorp/hcl/json/scanner",
							},
							{
								Value: "github.com/hashicorp/hcl/json/token",
							},
							{
								Value: "github.com/magiconair/properties",
							},
							{
								Value: "github.com/mitchellh/mapstructure",
							},
							{
								Value: "github.com/pelletier/go-toml",
							},
							{
								Value: "github.com/shirou/gopsutil/cpu",
							},
							{
								Value: "github.com/shirou/gopsutil/internal/common",
							},
							{
								Value: "github.com/shirou/gopsutil/mem",
							},
							{
								Value: "github.com/spf13/afero",
							},
							{
								Value: "github.com/spf13/afero/mem",
							},
							{
								Value: "github.com/spf13/cast",
							},
							{
								Value: "github.com/spf13/jwalterweatherman",
							},
							{
								Value: "github.com/spf13/pflag",
							},
							{
								Value: "github.com/spf13/viper",
							},
							{
								Value: "github.com/subosito/gotenv",
							},
							{
								Value: "github.com/wille/osutil",
							},
							{
								Value: "golang.org/x/net/http/httpguts",
							},
							{
								Value: "golang.org/x/net/http2",
							},
							{
								Value: "golang.org/x/net/http2/hpack",
							},
							{
								Value: "golang.org/x/net/idna",
							},
							{
								Value: "golang.org/x/net/internal/timeseries",
							},
							{
								Value: "golang.org/x/net/trace",
							},
							{
								Value: "golang.org/x/sys/unix",
							},
							{
								Value: "golang.org/x/text/secure/bidirule",
							},
							{
								Value: "golang.org/x/text/transform",
							},
							{
								Value: "golang.org/x/text/unicode/bidi",
							},
							{
								Value: "golang.org/x/text/unicode/norm",
							},
							{
								Value: "google.golang.org/genproto/googleapis/rpc/status",
							},
							{
								Value: "google.golang.org/grpc",
							},
							{
								Value: "google.golang.org/grpc/attributes",
							},
							{
								Value: "google.golang.org/grpc/balancer",
							},
							{
								Value: "google.golang.org/grpc/balancer/base",
							},
							{
								Value: "google.golang.org/grpc/balancer/roundrobin",
							},
							{
								Value: "google.golang.org/grpc/binarylog/grpc_binarylog_v1",
							},
							{
								Value: "google.golang.org/grpc/codes",
							},
							{
								Value: "google.golang.org/grpc/connectivity",
							},
							{
								Value: "google.golang.org/grpc/credentials",
							},
							{
								Value: "google.golang.org/grpc/encoding",
							},
							{
								Value: "google.golang.org/grpc/encoding/proto",
							},
							{
								Value: "google.golang.org/grpc/grpclog",
							},
							{
								Value: "google.golang.org/grpc/internal/backoff",
							},
							{
								Value: "google.golang.org/grpc/internal/binarylog",
							},
							{
								Value: "google.golang.org/grpc/internal/buffer",
							},
							{
								Value: "google.golang.org/grpc/internal/channelz",
							},
							{
								Value: "google.golang.org/grpc/internal/credentials",
							},
							{
								Value: "google.golang.org/grpc/internal/envconfig",
							},
							{
								Value: "google.golang.org/grpc/internal/grpclog",
							},
							{
								Value: "google.golang.org/grpc/internal/grpcrand",
							},
							{
								Value: "google.golang.org/grpc/internal/grpcsync",
							},
							{
								Value: "google.golang.org/grpc/internal/grpcutil",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver/dns",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver/passthrough",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver/unix",
							},
							{
								Value: "google.golang.org/grpc/internal/serviceconfig",
							},
							{
								Value: "google.golang.org/grpc/internal/status",
							},
							{
								Value: "google.golang.org/grpc/internal/syscall",
							},
							{
								Value: "google.golang.org/grpc/internal/transport",
							},
							{
								Value: "google.golang.org/grpc/metadata",
							},
							{
								Value: "google.golang.org/grpc/resolver",
							},
							{
								Value: "google.golang.org/grpc/stats",
							},
							{
								Value: "google.golang.org/grpc/status",
							},
							{
								Value: "google.golang.org/protobuf/encoding/prototext",
							},
							{
								Value: "google.golang.org/protobuf/encoding/protowire",
							},
							{
								Value: "google.golang.org/protobuf/internal/descfmt",
							},
							{
								Value: "google.golang.org/protobuf/internal/detrand",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/defval",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/messageset",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/tag",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/text",
							},
							{
								Value: "google.golang.org/protobuf/internal/errors",
							},
							{
								Value: "google.golang.org/protobuf/internal/filedesc",
							},
							{
								Value: "google.golang.org/protobuf/internal/filetype",
							},
							{
								Value: "google.golang.org/protobuf/internal/impl",
							},
							{
								Value: "google.golang.org/protobuf/internal/order",
							},
							{
								Value: "google.golang.org/protobuf/internal/strs",
							},
							{
								Value: "google.golang.org/protobuf/proto",
							},
							{
								Value: "google.golang.org/protobuf/reflect/protoreflect",
							},
							{
								Value: "google.golang.org/protobuf/reflect/protoregistry",
							},
							{
								Value: "google.golang.org/protobuf/types/descriptorpb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/anypb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/durationpb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/timestamppb",
							},
							{
								Value: "gopkg.in/ini%2ev1",
							},
							{
								Value: "gopkg.in/yaml%2ev2",
							},
							{
								Value: "howett.net/plist",
							},
							{
								Value: "proxit.com/cnc/grpcmodels",
							},
							{
								Value: "proxit.com/common",
							},
							{
								Value: "proxit.com/common/config",
							},
							{
								Value: "proxit.com/common/dns",
							},
							{
								Value: "proxit.com/common/hostinfo",
							},
							{
								Value: "proxit.com/common/logger",
							},
							{
								Value: "proxit.com/common/messages",
							},
						},
					},
				},
			},
		})
}

func TestUnsupportedGoMachoFile(t *testing.T) {
	baseRunTest(t, "ab439265ee7ac5c7d1a5db7fcdf1351b4e2bb074c132ecb3b2f9d70bd2f2a644",
		"Benign Mach-O.",
		&plugin.TestJobResult{
			Status:  "opt-out",
			Message: "Gore paniced while trying to open the file with the panic message: 'Unsupported architecture'",
		})
}

func TestCompilerFlags(t *testing.T) {
	baseRunTest(t, "02b95512919ca6785a00328da6424fd0a48796a17b36eb8e2317df9fe99071a1",
		"Benign arduino language server.",
		&plugin.TestJobResult{
			Status: "completed",
			Events: []plugin.TestJobEvent{
				{
					Features: map[string][]plugin.TestBinaryEntityFeature{
						"go_build_id": {
							{
								Value: "bKw81hXlQChlQkcvftbb/mq1A1-C5ihsWtVOIFJ02/-XVEBIxottcfGMedvTjh/05mmCGc2E86IXdtkyAYm",
							},
						},
						"go_compiler_flag": {
							{
								Label: "CGO_CFLAGS",
							},
							{
								Label: "CGO_CPPFLAGS",
							},
							{
								Label: "CGO_CXXFLAGS",
							},
							{
								Label: "CGO_LDFLAGS",
							},
							{
								Value: " -X github.com/arduino/arduino-language-server/version.versionString=0.7.1 -X github.com/arduino/arduino-language-server/version.commit=25afeae -X github.com/arduino/arduino-language-server/version.date=2022-07-15T14:50:42Z ",
								Label: "-ldflags",
							},
							{
								Value: "1",
								Label: "CGO_ENABLED",
							},
							{
								Value: "2022-07-15T14:49:45Z",
								Label: "vcs.time",
							},
							{
								Value: "25afeae89a9b34b0ffe50e28c928ad290b2b0662",
								Label: "vcs.revision",
							},
							{
								Value: "amd64",
								Label: "GOARCH",
							},
							{
								Value: "darwin",
								Label: "GOOS",
							},
							{
								Value: "gc",
								Label: "-compiler",
							},
							{
								Value: "git",
								Label: "vcs",
							},
							{
								Value: "true",
								Label: "vcs.modified",
							},
							{
								Value: "v1",
								Label: "GOAMD64",
							},
						},
						"go_compiler_timestamp": {
							{
								Value: "2022-06-01T16:38:24Z",
							},
						},
						"go_compiler_version": {
							{
								Value: "go1.18.3",
							},
						},
						"go_file": {
							{
								Value: "/home/build",
							},
							{
								Value: "/home/build/ls",
							},
							{
								Value: "/home/build/sourcemapper",
							},
							{
								Value: "/home/build/streams",
							},
						},
						"go_package": {
							{
								Value: "github.com/arduino/arduino-language-server/ls",
							},
							{
								Value: "github.com/arduino/arduino-language-server/sourcemapper",
							},
							{
								Value: "github.com/arduino/arduino-language-server/streams",
							},
							{
								Value: "main",
							},
						},
						"go_package_function": {
							{
								Value:  "CatchAndLogPanic",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   352,
								Offset: 73036480,
							},
							{
								Value:  "NewClangdLSPClient",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3136,
								Offset: 73172096,
							},
							{
								Value:  "NewIDELSPServer",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   672,
								Offset: 73181600,
							},
							{
								Value:  "NewINOLanguageServer",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1440,
								Offset: 73061472,
							},
							{
								Value:  "NewProgressProxy",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   288,
								Offset: 73187712,
							},
							{
								Value:  "NewSketchBuilder",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   256,
								Offset: 73049248,
							},
							{
								Value:  "OpenLogFileAs",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   320,
								Offset: 73035104,
							},
							{
								Value:  "canonicalizeCompileCommandsJSON",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   480,
								Offset: 73059616,
							},
							{
								Value:  "init",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73194048,
							},
							{
								Value:  "init",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   320,
								Offset: 73034208,
							},
							{
								Value:  "main",
								Label:  "main",
								Size:   4714,
								Offset: 73195648,
							},
							{
								Value:  "unquoteCppString",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   384,
								Offset: 73027168,
							},
						},
						"go_package_method": {
							{
								Value:  "0",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176928,
							},
							{
								Value:  "1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73068192,
							},
							{
								Value:  "2",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73068384,
							},
							{
								Value:  "ApplyTextChange",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   1536,
								Offset: 73027552,
							},
							{
								Value:  "ArduinoBuildCompleted",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   384,
								Offset: 73187328,
							},
							{
								Value:  "ArduinoBuildCompleted-fm",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73194752,
							},
							{
								Value:  "Begin",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   448,
								Offset: 73191552,
							},
							{
								Value:  "CallHierarchyIncomingCalls",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185408,
							},
							{
								Value:  "CallHierarchyOutgoingCalls",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185472,
							},
							{
								Value:  "CleanUp",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73128224,
							},
							{
								Value:  "ClientRegisterCapability",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175808,
							},
							{
								Value:  "ClientUnregisterCapability",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175872,
							},
							{
								Value:  "Close",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   224,
								Offset: 73127968,
							},
							{
								Value:  "Close",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175488,
							},
							{
								Value:  "Close",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   224,
								Offset: 73036256,
							},
							{
								Value:  "Close",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   160,
								Offset: 73037056,
							},
							{
								Value:  "CloseNotify",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73128192,
							},
							{
								Value:  "CodeActionResolve",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184320,
							},
							{
								Value:  "CodeLensResolve",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184448,
							},
							{
								Value:  "CompletionItemResolve",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73183104,
							},
							{
								Value:  "CopyFullBuildResults",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   512,
								Offset: 73118336,
							},
							{
								Value:  "CppToInoLine",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   96,
								Offset: 73023680,
							},
							{
								Value:  "CppToInoLineOk",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   128,
								Offset: 73024864,
							},
							{
								Value:  "CppToInoRange",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   160,
								Offset: 73023776,
							},
							{
								Value:  "CppToInoRangeOk",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   896,
								Offset: 73023968,
							},
							{
								Value:  "Create",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   416,
								Offset: 73191040,
							},
							{
								Value:  "DebugLogAll",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   1280,
								Offset: 73032928,
							},
							{
								Value:  "DocumentLinkResolve",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184576,
							},
							{
								Value:  "End",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   384,
								Offset: 73192608,
							},
							{
								Value:  "Error",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   160,
								Offset: 73137600,
							},
							{
								Value:  "Error",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   32,
								Offset: 73023936,
							},
							{
								Value:  "Error",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   96,
								Offset: 73034528,
							},
							{
								Value:  "Exit",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73186112,
							},
							{
								Value:  "ExitNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   160,
								Offset: 73107808,
							},
							{
								Value:  "FullBuildCompletedFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   480,
								Offset: 73117760,
							},
							{
								Value:  "Initialize",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73182336,
							},
							{
								Value:  "InitializeReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2400,
								Offset: 73063104,
							},
							{
								Value:  "Initialized",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73185984,
							},
							{
								Value:  "InitializedNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73107680,
							},
							{
								Value:  "InoToCppLSPRange",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   512,
								Offset: 73022720,
							},
							{
								Value:  "InoToCppLSPRangeOk",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   448,
								Offset: 73023232,
							},
							{
								Value:  "InoToCppLine",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   256,
								Offset: 73022208,
							},
							{
								Value:  "InoToCppLineOk",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   256,
								Offset: 73022464,
							},
							{
								Value:  "IsPreprocessedCppLine",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   160,
								Offset: 73024992,
							},
							{
								Value:  "LogIncomingCancelRequest",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   320,
								Offset: 73179520,
							},
							{
								Value:  "LogIncomingDataDelay",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73181088,
							},
							{
								Value:  "LogIncomingNotification",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   576,
								Offset: 73180512,
							},
							{
								Value:  "LogIncomingRequest",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   736,
								Offset: 73178784,
							},
							{
								Value:  "LogIncomingResponse",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   672,
								Offset: 73177760,
							},
							{
								Value:  "LogOutgoingCancelRequest",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   320,
								Offset: 73177440,
							},
							{
								Value:  "LogOutgoingDataDelay",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73181216,
							},
							{
								Value:  "LogOutgoingNotification",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   352,
								Offset: 73178432,
							},
							{
								Value:  "LogOutgoingRequest",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   448,
								Offset: 73176992,
							},
							{
								Value:  "LogOutgoingResponse",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   672,
								Offset: 73179840,
							},
							{
								Value:  "LogTrace",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176320,
							},
							{
								Value:  "Logf",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   256,
								Offset: 73181344,
							},
							{
								Value:  "Progress",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73176192,
							},
							{
								Value:  "Progress",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185920,
							},
							{
								Value:  "ProgressNotifFromClangd",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1536,
								Offset: 73125696,
							},
							{
								Value:  "PublishDiagnosticsNotifFromClangd",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3904,
								Offset: 73118848,
							},
							{
								Value:  "Read",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   416,
								Offset: 73035424,
							},
							{
								Value:  "Read",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   96,
								Offset: 73036832,
							},
							{
								Value:  "Report",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   416,
								Offset: 73192096,
							},
							{
								Value:  "Run",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175424,
							},
							{
								Value:  "Run",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182272,
							},
							{
								Value:  "SetTrace",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73186208,
							},
							{
								Value:  "SetTraceNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   256,
								Offset: 73127712,
							},
							{
								Value:  "Shutdown",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73182464,
							},
							{
								Value:  "Shutdown",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   864,
								Offset: 73193088,
							},
							{
								Value:  "ShutdownReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   256,
								Offset: 73068480,
							},
							{
								Value:  "TelemetryEvent",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176512,
							},
							{
								Value:  "TextDocumentCodeAction",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73184192,
							},
							{
								Value:  "TextDocumentCodeActionReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   5792,
								Offset: 73094976,
							},
							{
								Value:  "TextDocumentCodeLens",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184384,
							},
							{
								Value:  "TextDocumentColorPresentation",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184704,
							},
							{
								Value:  "TextDocumentCompletion",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73182976,
							},
							{
								Value:  "TextDocumentCompletionReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   5408,
								Offset: 73068832,
							},
							{
								Value:  "TextDocumentDeclaration",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73183424,
							},
							{
								Value:  "TextDocumentDefinition",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73183488,
							},
							{
								Value:  "TextDocumentDefinitionReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2784,
								Offset: 73079584,
							},
							{
								Value:  "TextDocumentDidChange",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73186880,
							},
							{
								Value:  "TextDocumentDidChangeNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   4736,
								Offset: 73110432,
							},
							{
								Value:  "TextDocumentDidClose",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73187200,
							},
							{
								Value:  "TextDocumentDidCloseNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2016,
								Offset: 73115648,
							},
							{
								Value:  "TextDocumentDidOpen",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73186752,
							},
							{
								Value:  "TextDocumentDidOpenNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2368,
								Offset: 73107968,
							},
							{
								Value:  "TextDocumentDidSave",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73187072,
							},
							{
								Value:  "TextDocumentDidSaveNotifFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   288,
								Offset: 73115264,
							},
							{
								Value:  "TextDocumentDocumentColor",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184640,
							},
							{
								Value:  "TextDocumentDocumentHighlight",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73183936,
							},
							{
								Value:  "TextDocumentDocumentHighlightReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3360,
								Offset: 73088224,
							},
							{
								Value:  "TextDocumentDocumentLink",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73184512,
							},
							{
								Value:  "TextDocumentDocumentSymbol",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73184064,
							},
							{
								Value:  "TextDocumentDocumentSymbolReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3200,
								Offset: 73091680,
							},
							{
								Value:  "TextDocumentFoldingRange",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185216,
							},
							{
								Value:  "TextDocumentFormatting",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73184768,
							},
							{
								Value:  "TextDocumentFormattingReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3360,
								Offset: 73100864,
							},
							{
								Value:  "TextDocumentHover",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73183168,
							},
							{
								Value:  "TextDocumentHoverReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3136,
								Offset: 73074336,
							},
							{
								Value:  "TextDocumentImplementation",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73183744,
							},
							{
								Value:  "TextDocumentImplementationReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2784,
								Offset: 73085344,
							},
							{
								Value:  "TextDocumentLinkedEditingRange",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185792,
							},
							{
								Value:  "TextDocumentMoniker",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185856,
							},
							{
								Value:  "TextDocumentOnTypeFormatting",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185024,
							},
							{
								Value:  "TextDocumentPrepareCallHierarchy",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185344,
							},
							{
								Value:  "TextDocumentPublishDiagnostics",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   256,
								Offset: 73176576,
							},
							{
								Value:  "TextDocumentRangeFormatting",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73184896,
							},
							{
								Value:  "TextDocumentRangeFormattingReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   3264,
								Offset: 73104320,
							},
							{
								Value:  "TextDocumentReferences",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73183872,
							},
							{
								Value:  "TextDocumentRename",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73185088,
							},
							{
								Value:  "TextDocumentRenameReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2592,
								Offset: 73122848,
							},
							{
								Value:  "TextDocumentSelectionRange",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185280,
							},
							{
								Value:  "TextDocumentSemanticTokensFull",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185536,
							},
							{
								Value:  "TextDocumentSemanticTokensFullDelta",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185600,
							},
							{
								Value:  "TextDocumentSemanticTokensRange",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185664,
							},
							{
								Value:  "TextDocumentSignatureHelp",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73183296,
							},
							{
								Value:  "TextDocumentSignatureHelpReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1920,
								Offset: 73077568,
							},
							{
								Value:  "TextDocumentTypeDefinition",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73183616,
							},
							{
								Value:  "TextDocumentTypeDefinitionReqFromIDE",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2784,
								Offset: 73082464,
							},
							{
								Value:  "TextDocumentWillSave",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73187008,
							},
							{
								Value:  "TextDocumentWillSaveWaitUntil",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182912,
							},
							{
								Value:  "TriggerRebuild",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   256,
								Offset: 73049824,
							},
							{
								Value:  "WindowLogMessage",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176448,
							},
							{
								Value:  "WindowShowDocument",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175616,
							},
							{
								Value:  "WindowShowMessage",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176384,
							},
							{
								Value:  "WindowShowMessageRequest",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175552,
							},
							{
								Value:  "WindowWorkDoneProgressCancel",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73186336,
							},
							{
								Value:  "WindowWorkDoneProgressCreate",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73175680,
							},
							{
								Value:  "WindowWorkDoneProgressCreateReqFromClangd",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   480,
								Offset: 73127232,
							},
							{
								Value:  "WorkspaceApplyEdit",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176064,
							},
							{
								Value:  "WorkspaceCodeLensRefresh",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176128,
							},
							{
								Value:  "WorkspaceConfiguration",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73176000,
							},
							{
								Value:  "WorkspaceDidChangeConfiguration",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73186464,
							},
							{
								Value:  "WorkspaceDidChangeWatchedFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73186496,
							},
							{
								Value:  "WorkspaceDidChangeWorkspaceFolders",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73186400,
							},
							{
								Value:  "WorkspaceDidCreateFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73186560,
							},
							{
								Value:  "WorkspaceDidDeleteFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73186688,
							},
							{
								Value:  "WorkspaceDidRenameFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73186624,
							},
							{
								Value:  "WorkspaceExecuteCommand",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182656,
							},
							{
								Value:  "WorkspaceSemanticTokensRefresh",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73185728,
							},
							{
								Value:  "WorkspaceSymbol",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182592,
							},
							{
								Value:  "WorkspaceWillCreateFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182720,
							},
							{
								Value:  "WorkspaceWillDeleteFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182848,
							},
							{
								Value:  "WorkspaceWillRenameFiles",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73182784,
							},
							{
								Value:  "WorkspaceWorkspaceFolders",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   64,
								Offset: 73175936,
							},
							{
								Value:  "Write",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   416,
								Offset: 73035840,
							},
							{
								Value:  "Write",
								Label:  "github.com/arduino/arduino-language-server/streams",
								Size:   128,
								Offset: 73036928,
							},
							{
								Value:  "addInoLine",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   2432,
								Offset: 73029088,
							},
							{
								Value:  "cland2IdeTextEdits",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2944,
								Offset: 73153600,
							},
							{
								Value:  "clang2IdeCodeAction",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   960,
								Offset: 73131296,
							},
							{
								Value:  "clang2IdeCommand",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1376,
								Offset: 73132256,
							},
							{
								Value:  "clang2IdeDiagnostic",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   896,
								Offset: 73147616,
							},
							{
								Value:  "clang2IdeDiagnosticRelatedInformationArray",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   992,
								Offset: 73148512,
							},
							{
								Value:  "clang2IdeDiagnostics",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1920,
								Offset: 73145696,
							},
							{
								Value:  "clang2IdeDocumentHighlight",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   544,
								Offset: 73145152,
							},
							{
								Value:  "clang2IdeDocumentSymbols",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   4096,
								Offset: 73149504,
							},
							{
								Value:  "clang2IdeDocumentURI",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2752,
								Offset: 73142400,
							},
							{
								Value:  "clang2IdeLocation",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   480,
								Offset: 73157728,
							},
							{
								Value:  "clang2IdeLocationsArray",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1184,
								Offset: 73156544,
							},
							{
								Value:  "clang2IdeRangeAndDocumentURI",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   4480,
								Offset: 73137920,
							},
							{
								Value:  "clang2IdeTextEdit",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   800,
								Offset: 73159648,
							},
							{
								Value:  "clang2IdeWorkspaceEdit",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1440,
								Offset: 73158208,
							},
							{
								Value:  "clangURIRefersToIno",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   160,
								Offset: 73137760,
							},
							{
								Value:  "cpp2inoTextEdit",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1792,
								Offset: 73135808,
							},
							{
								Value:  "cpp2inoWorkspaceEdit",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2176,
								Offset: 73133632,
							},
							{
								Value:  "createClangdFormatterConfig",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   928,
								Offset: 73160448,
							},
							{
								Value:  "deleteCppLine",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   1408,
								Offset: 73031520,
							},
							{
								Value:  "doRebuildArduinoPreprocessedSketch",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2272,
								Offset: 73051040,
							},
							{
								Value:  "extractDataFolderFromArduinoCLI",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2784,
								Offset: 73128416,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73049216,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73050080,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73053312,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73062912,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2688,
								Offset: 73065504,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73068736,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73074240,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73077472,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73079488,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73082368,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73085248,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73088128,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73091584,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73094880,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73100768,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73104224,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73107584,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73110336,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73115168,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73115552,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73117664,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73118240,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73122752,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73125440,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   448,
								Offset: 73161504,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73175328,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73176832,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73188000,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73188672,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73191456,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73192000,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73192512,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73192992,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73193952,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73194176,
							},
							{
								Value:  "func1",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73194240,
							},
							{
								Value:  "func1",
								Label:  "main",
								Size:   160,
								Offset: 73195488,
							},
							{
								Value:  "func2",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73049504,
							},
							{
								Value:  "func2",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   128,
								Offset: 73161376,
							},
							{
								Value:  "func2",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73175232,
							},
							{
								Value:  "func2",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73194208,
							},
							{
								Value:  "func2",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   32,
								Offset: 73194272,
							},
							{
								Value:  "func3",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73059520,
							},
							{
								Value:  "func3",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73131200,
							},
							{
								Value:  "func4",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   96,
								Offset: 73059424,
							},
							{
								Value:  "generateBuildEnvironment",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   6016,
								Offset: 73053408,
							},
							{
								Value:  "handleProxy",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2272,
								Offset: 73188768,
							},
							{
								Value:  "handlerLoop",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   544,
								Offset: 73188128,
							},
							{
								Value:  "ide2ClangCodeActionContext",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1184,
								Offset: 73170912,
							},
							{
								Value:  "ide2ClangDiagnostic",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1120,
								Offset: 73169792,
							},
							{
								Value:  "ide2ClangDiagnosticRelatedInformationArray",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   896,
								Offset: 73168416,
							},
							{
								Value:  "ide2ClangDocumentURI",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   2400,
								Offset: 73163200,
							},
							{
								Value:  "ide2ClangLocation",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   480,
								Offset: 73169312,
							},
							{
								Value:  "ide2ClangPosition",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   416,
								Offset: 73166752,
							},
							{
								Value:  "ide2ClangRange",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1248,
								Offset: 73167168,
							},
							{
								Value:  "ide2ClangTextDocumentPositionParams",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1152,
								Offset: 73165600,
							},
							{
								Value:  "idePathToIdeURI",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   1248,
								Offset: 73161952,
							},
							{
								Value:  "ideURIIsPartOfTheSketch",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   160,
								Offset: 73125536,
							},
							{
								Value:  "readLock",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   512,
								Offset: 73060768,
							},
							{
								Value:  "readUnlock",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73061280,
							},
							{
								Value:  "rebuilderLoop",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   864,
								Offset: 73050176,
							},
							{
								Value:  "regeneratehMapping",
								Label:  "github.com/arduino/arduino-language-server/sourcemapper",
								Size:   2016,
								Offset: 73025152,
							},
							{
								Value:  "triggerRebuildAndWait",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73049632,
							},
							{
								Value:  "writeLock",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   480,
								Offset: 73060096,
							},
							{
								Value:  "writeUnlock",
								Label:  "github.com/arduino/arduino-language-server/ls",
								Size:   192,
								Offset: 73060576,
							},
						},
						"go_type": {
							{
								Value:  "*ls.ClangdLSPClient",
								Label:  "ptr",
								Offset: 74578016,
							},
							{
								Value:  "*ls.IDELSPServer",
								Label:  "ptr",
								Offset: 74720096,
							},
							{
								Value:  "*ls.INOLanguageServer",
								Label:  "ptr",
								Offset: 74732416,
							},
							{
								Value:  "*ls.LSPFunctionLogger",
								Label:  "ptr",
								Offset: 73764000,
							},
							{
								Value:  "*ls.LSPLogger",
								Label:  "ptr",
								Offset: 74462144,
							},
							{
								Value:  "*ls.ProgressProxyHandler",
								Label:  "ptr",
								Offset: 74310688,
							},
							{
								Value:  "*ls.SketchRebuilder",
								Label:  "ptr",
								Offset: 73953184,
							},
							{
								Value:  "*ls.UnknownURI",
								Label:  "ptr",
								Offset: 73764096,
							},
							{
								Value:  "*sourcemapper.AdjustedRangeErr",
								Label:  "ptr",
								Offset: 73764192,
							},
							{
								Value:  "*sourcemapper.SketchMapper",
								Label:  "ptr",
								Offset: 74550112,
							},
							{
								Value:  "*streams.combinedReadWriteCloser",
								Label:  "ptr",
								Offset: 73953312,
							},
							{
								Value:  "*streams.dumper",
								Label:  "ptr",
								Offset: 73953440,
							},
							{
								Value:  "ls.ClangdLSPClient",
								Label:  "struct",
								Offset: 74072800,
							},
							{
								Value:  "ls.IDELSPServer",
								Label:  "struct",
								Offset: 74072960,
							},
							{
								Value:  "ls.INOLanguageServer",
								Label:  "struct",
								Offset: 74645152,
							},
							{
								Value:  "ls.LSPFunctionLogger",
								Label:  "struct",
								Offset: 74073120,
							},
							{
								Value:  "ls.ProgressProxyHandler",
								Label:  "struct",
								Offset: 74346208,
							},
							{
								Value:  "ls.SketchRebuilder",
								Label:  "struct",
								Offset: 74346400,
							},
							{
								Value:  "ls.progressProxy",
								Label:  "struct",
								Offset: 74428128,
							},
							{
								Value:  "sourcemapper.SketchMapper",
								Label:  "struct",
								Offset: 74428352,
							},
							{
								Value:  "streams.combinedReadWriteCloser",
								Label:  "struct",
								Offset: 74073760,
							},
							{
								Value:  "streams.dumper",
								Label:  "struct",
								Offset: 74346784,
							},
						},
						"go_type_method": {
							{
								Value: "ApplyTextChange",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "ArduinoBuildCompleted",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "Begin",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "CallHierarchyIncomingCalls",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "CallHierarchyOutgoingCalls",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "CleanUp",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ClientRegisterCapability",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "ClientUnregisterCapability",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "Close",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "Close",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "Close",
								Label: "*streams.combinedReadWriteCloser",
							},
							{
								Value: "Close",
								Label: "*streams.dumper",
							},
							{
								Value: "CloseNotify",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "CodeActionResolve",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "CodeLensResolve",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "CompletionItemResolve",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "CopyFullBuildResults",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "CppToInoLine",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "CppToInoLineOk",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "CppToInoRange",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "CppToInoRangeOk",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "Create",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "DebugLogAll",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "DocumentLinkResolve",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "End",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "Error",
								Label: "*ls.UnknownURI",
							},
							{
								Value: "Error",
								Label: "*sourcemapper.AdjustedRangeErr",
							},
							{
								Value: "Exit",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "ExitNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "FullBuildCompletedFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "Initialize",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "InitializeReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "Initialized",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "InitializedNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "InoToCppLSPRange",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "InoToCppLSPRangeOk",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "InoToCppLine",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "InoToCppLineOk",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "IsPreprocessedCppLine",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "LogIncomingCancelRequest",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogIncomingDataDelay",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogIncomingNotification",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogIncomingRequest",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogIncomingResponse",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogOutgoingCancelRequest",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogOutgoingDataDelay",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogOutgoingNotification",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogOutgoingRequest",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogOutgoingResponse",
								Label: "*ls.LSPLogger",
							},
							{
								Value: "LogTrace",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "Logf",
								Label: "*ls.LSPFunctionLogger",
							},
							{
								Value: "Progress",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "Progress",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "ProgressNotifFromClangd",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "PublishDiagnosticsNotifFromClangd",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "Read",
								Label: "*streams.combinedReadWriteCloser",
							},
							{
								Value: "Read",
								Label: "*streams.dumper",
							},
							{
								Value: "Report",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "Run",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "Run",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "SetTrace",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "SetTraceNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "Shutdown",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "Shutdown",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "ShutdownReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TelemetryEvent",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "TextDocumentCodeAction",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentCodeActionReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentCodeLens",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentColorPresentation",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentCompletion",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentCompletionReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDeclaration",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDefinition",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDefinitionReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDidChange",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDidChangeNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDidClose",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDidCloseNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDidOpen",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDidOpenNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDidSave",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDidSaveNotifFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDocumentColor",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDocumentHighlight",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDocumentHighlightReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentDocumentLink",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDocumentSymbol",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentDocumentSymbolReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentFoldingRange",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentFormatting",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentFormattingReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentHover",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentHoverReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentImplementation",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentImplementationReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentLinkedEditingRange",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentMoniker",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentOnTypeFormatting",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentPrepareCallHierarchy",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentPublishDiagnostics",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "TextDocumentRangeFormatting",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentRangeFormattingReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentReferences",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentRename",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentRenameReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentSelectionRange",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentSemanticTokensFull",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentSemanticTokensFullDelta",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentSemanticTokensRange",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentSignatureHelp",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentSignatureHelpReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentTypeDefinition",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentTypeDefinitionReqFromIDE",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "TextDocumentWillSave",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TextDocumentWillSaveWaitUntil",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "TriggerRebuild",
								Label: "*ls.SketchRebuilder",
							},
							{
								Value: "WindowLogMessage",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WindowShowDocument",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WindowShowMessage",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WindowShowMessageRequest",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WindowWorkDoneProgressCancel",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WindowWorkDoneProgressCreate",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WindowWorkDoneProgressCreateReqFromClangd",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "WorkspaceApplyEdit",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WorkspaceCodeLensRefresh",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WorkspaceConfiguration",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "WorkspaceDidChangeConfiguration",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceDidChangeWatchedFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceDidChangeWorkspaceFolders",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceDidCreateFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceDidDeleteFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceDidRenameFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceExecuteCommand",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceSemanticTokensRefresh",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceSymbol",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceWillCreateFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceWillDeleteFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceWillRenameFiles",
								Label: "*ls.IDELSPServer",
							},
							{
								Value: "WorkspaceWorkspaceFolders",
								Label: "*ls.ClangdLSPClient",
							},
							{
								Value: "Write",
								Label: "*streams.combinedReadWriteCloser",
							},
							{
								Value: "Write",
								Label: "*streams.dumper",
							},
							{
								Value: "addInoLine",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "cland2IdeTextEdits",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeCodeAction",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeCommand",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeDiagnostic",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeDiagnosticRelatedInformationArray",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeDiagnostics",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeDocumentHighlight",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeDocumentSymbols",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeDocumentURI",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeLocation",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeLocationsArray",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeRangeAndDocumentURI",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeSymbolTags",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeSymbolsInformation",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeTextEdit",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clang2IdeWorkspaceEdit",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "clangURIRefersToIno",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "cpp2inoTextEdit",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "cpp2inoWorkspaceEdit",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "createClangdFormatterConfig",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "deleteCppLine",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "doRebuildArduinoPreprocessedSketch",
								Label: "*ls.SketchRebuilder",
							},
							{
								Value: "extractDataFolderFromArduinoCLI",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "generateBuildEnvironment",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "handleError",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "handleProxy",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "handlerLoop",
								Label: "*ls.ProgressProxyHandler",
							},
							{
								Value: "ide2ClangCodeActionContext",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangDiagnostic",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangDiagnosticRelatedInformationArray",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangDocumentURI",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangLocation",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangPosition",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangRange",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangTextDocumentIdentifier",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangTextDocumentPositionParams",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ide2ClangVersionedTextDocumentIdentifier",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "idePathToIdeURI",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "ideURIIsPartOfTheSketch",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "mapLine",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "readLock",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "readUnlock",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "rebuilderLoop",
								Label: "*ls.SketchRebuilder",
							},
							{
								Value: "regeneratehMapping",
								Label: "*sourcemapper.SketchMapper",
							},
							{
								Value: "showMessage",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "triggerRebuild",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "triggerRebuildAndWait",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "writeLock",
								Label: "*ls.INOLanguageServer",
							},
							{
								Value: "writeUnlock",
								Label: "*ls.INOLanguageServer",
							},
						},
						"go_vendor_package": {
							{
								Value: "github.com/arduino/arduino-cli/arduino",
							},
							{
								Value: "github.com/arduino/arduino-cli/arduino/builder",
							},
							{
								Value: "github.com/arduino/arduino-cli/arduino/cores",
							},
							{
								Value: "github.com/arduino/arduino-cli/arduino/globals",
							},
							{
								Value: "github.com/arduino/arduino-cli/arduino/httpclient",
							},
							{
								Value: "github.com/arduino/arduino-cli/arduino/libraries",
							},
							{
								Value: "github.com/arduino/arduino-cli/arduino/resources",
							},
							{
								Value: "github.com/arduino/arduino-cli/cli/feedback",
							},
							{
								Value: "github.com/arduino/arduino-cli/cli/globals",
							},
							{
								Value: "github.com/arduino/arduino-cli/configuration",
							},
							{
								Value: "github.com/arduino/arduino-cli/executils",
							},
							{
								Value: "github.com/arduino/arduino-cli/i18n",
							},
							{
								Value: "github.com/arduino/arduino-cli/rpc/cc/arduino/cli/commands/v1",
							},
							{
								Value: "github.com/arduino/arduino-cli/rpc/cc/arduino/cli/settings/v1",
							},
							{
								Value: "github.com/arduino/arduino-cli/version",
							},
							{
								Value: "github.com/arduino/go-paths-helper",
							},
							{
								Value: "github.com/arduino/go-properties-orderedmap",
							},
							{
								Value: "github.com/codeclysm/extract/v3",
							},
							{
								Value: "github.com/djherbis/buffer",
							},
							{
								Value: "github.com/djherbis/buffer/limio",
							},
							{
								Value: "github.com/djherbis/buffer/wrapio",
							},
							{
								Value: "github.com/fatih/color",
							},
							{
								Value: "github.com/fsnotify/fsnotify",
							},
							{
								Value: "github.com/golang/protobuf/proto",
							},
							{
								Value: "github.com/golang/protobuf/ptypes",
							},
							{
								Value: "github.com/golang/protobuf/ptypes/any",
							},
							{
								Value: "github.com/golang/protobuf/ptypes/duration",
							},
							{
								Value: "github.com/golang/protobuf/ptypes/timestamp",
							},
							{
								Value: "github.com/h2non/filetype",
							},
							{
								Value: "github.com/h2non/filetype/matchers",
							},
							{
								Value: "github.com/h2non/filetype/types",
							},
							{
								Value: "github.com/hashicorp/hcl",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/parser",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/strconv",
							},
							{
								Value: "github.com/hashicorp/hcl/hcl/token",
							},
							{
								Value: "github.com/hashicorp/hcl/json/parser",
							},
							{
								Value: "github.com/juju/errors",
							},
							{
								Value: "github.com/leonelquinteros/gotext",
							},
							{
								Value: "github.com/leonelquinteros/gotext/plurals",
							},
							{
								Value: "github.com/mattn/go-isatty",
							},
							{
								Value: "github.com/pelletier/go-toml",
							},
							{
								Value: "github.com/pkg/errors",
							},
							{
								Value: "github.com/pmylund/sortutil",
							},
							{
								Value: "github.com/sirupsen/logrus",
							},
							{
								Value: "github.com/spf13/afero",
							},
							{
								Value: "github.com/spf13/afero/mem",
							},
							{
								Value: "github.com/spf13/cast",
							},
							{
								Value: "github.com/spf13/cobra",
							},
							{
								Value: "github.com/spf13/jwalterweatherman",
							},
							{
								Value: "github.com/spf13/pflag",
							},
							{
								Value: "github.com/spf13/viper",
							},
							{
								Value: "golang.org/x/net/http/httpguts",
							},
							{
								Value: "golang.org/x/net/http2",
							},
							{
								Value: "golang.org/x/net/http2/hpack",
							},
							{
								Value: "golang.org/x/net/idna",
							},
							{
								Value: "golang.org/x/net/internal/timeseries",
							},
							{
								Value: "golang.org/x/net/trace",
							},
							{
								Value: "golang.org/x/sys/unix",
							},
							{
								Value: "golang.org/x/text/secure/bidirule",
							},
							{
								Value: "golang.org/x/text/transform",
							},
							{
								Value: "golang.org/x/text/unicode/bidi",
							},
							{
								Value: "golang.org/x/text/unicode/norm",
							},
							{
								Value: "google.golang.org/genproto/googleapis/rpc/status",
							},
							{
								Value: "google.golang.org/grpc",
							},
							{
								Value: "google.golang.org/grpc/attributes",
							},
							{
								Value: "google.golang.org/grpc/balancer",
							},
							{
								Value: "google.golang.org/grpc/balancer/base",
							},
							{
								Value: "google.golang.org/grpc/balancer/roundrobin",
							},
							{
								Value: "google.golang.org/grpc/binarylog/grpc_binarylog_v1",
							},
							{
								Value: "google.golang.org/grpc/codes",
							},
							{
								Value: "google.golang.org/grpc/connectivity",
							},
							{
								Value: "google.golang.org/grpc/credentials",
							},
							{
								Value: "google.golang.org/grpc/encoding",
							},
							{
								Value: "google.golang.org/grpc/encoding/proto",
							},
							{
								Value: "google.golang.org/grpc/grpclog",
							},
							{
								Value: "google.golang.org/grpc/internal/backoff",
							},
							{
								Value: "google.golang.org/grpc/internal/binarylog",
							},
							{
								Value: "google.golang.org/grpc/internal/buffer",
							},
							{
								Value: "google.golang.org/grpc/internal/channelz",
							},
							{
								Value: "google.golang.org/grpc/internal/credentials",
							},
							{
								Value: "google.golang.org/grpc/internal/envconfig",
							},
							{
								Value: "google.golang.org/grpc/internal/grpclog",
							},
							{
								Value: "google.golang.org/grpc/internal/grpcrand",
							},
							{
								Value: "google.golang.org/grpc/internal/grpcsync",
							},
							{
								Value: "google.golang.org/grpc/internal/grpcutil",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver/dns",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver/passthrough",
							},
							{
								Value: "google.golang.org/grpc/internal/resolver/unix",
							},
							{
								Value: "google.golang.org/grpc/internal/serviceconfig",
							},
							{
								Value: "google.golang.org/grpc/internal/status",
							},
							{
								Value: "google.golang.org/grpc/internal/syscall",
							},
							{
								Value: "google.golang.org/grpc/internal/transport",
							},
							{
								Value: "google.golang.org/grpc/internal/xds/env",
							},
							{
								Value: "google.golang.org/grpc/metadata",
							},
							{
								Value: "google.golang.org/grpc/resolver",
							},
							{
								Value: "google.golang.org/grpc/stats",
							},
							{
								Value: "google.golang.org/grpc/status",
							},
							{
								Value: "google.golang.org/protobuf/encoding/prototext",
							},
							{
								Value: "google.golang.org/protobuf/encoding/protowire",
							},
							{
								Value: "google.golang.org/protobuf/internal/descfmt",
							},
							{
								Value: "google.golang.org/protobuf/internal/detrand",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/defval",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/messageset",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/tag",
							},
							{
								Value: "google.golang.org/protobuf/internal/encoding/text",
							},
							{
								Value: "google.golang.org/protobuf/internal/errors",
							},
							{
								Value: "google.golang.org/protobuf/internal/filedesc",
							},
							{
								Value: "google.golang.org/protobuf/internal/filetype",
							},
							{
								Value: "google.golang.org/protobuf/internal/impl",
							},
							{
								Value: "google.golang.org/protobuf/internal/order",
							},
							{
								Value: "google.golang.org/protobuf/internal/strs",
							},
							{
								Value: "google.golang.org/protobuf/proto",
							},
							{
								Value: "google.golang.org/protobuf/reflect/protoreflect",
							},
							{
								Value: "google.golang.org/protobuf/reflect/protoregistry",
							},
							{
								Value: "google.golang.org/protobuf/types/descriptorpb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/anypb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/durationpb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/timestamppb",
							},
							{
								Value: "google.golang.org/protobuf/types/known/wrapperspb",
							},
							{
								Value: "gopkg.in/ini%2ev1",
							},
							{
								Value: "gopkg.in/yaml%2ev2",
							},
						},
					},
				},
			},
		})
}
