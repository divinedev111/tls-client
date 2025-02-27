package tests

import (
	tls "github.com/bogdanfinn/utls"
	tls_client "github.com/divinedev111/tls-client"
)

const (
	chrome        = "chrome"
	firefox       = "firefox"
	opera         = "opera"
	safari        = "safari"
	safariIpadOs  = "safari_Ipad"
	safariIos     = "safari_IOS"
	okhttpAndroid = "okhttp_Android"

	peetApiEndpoint = "https://tls.peet.ws/api/all"

	ja3String             = "ja3String"
	ja3Hash               = "ja3Hash"
	akamaiFingerprint     = "akamaiFingerprint"
	akamaiFingerprintHash = "akamaiFingerprintHash"
)

var clientFingerprints = map[string]map[string]map[string]string{
	chrome: {
		tls.HelloChrome_112.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-51-17513-43-0-11-5-23-16-10-65281-27-18-35-13-21,29-23-24,0",
			ja3Hash:               "7f052aeccc9b50e9b3a43a02780539b2",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_111.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-11-17513-5-10-18-23-0-45-51-43-35-65281-16-13-21,29-23-24,0",
			ja3Hash:               "499d7c2439dc2fb83d1ab2e52b9dc680",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_110.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-27-18-51-17513-0-16-35-11-5-65281-43-13-45-10-21,29-23-24,0",
			ja3Hash:               "f30e7d05622c38802b2ee65d147f4df8",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_109.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_108.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_107.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_106.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "46cedabdca2073198a42fa10ca4494d0",
		},
		tls.HelloChrome_105.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "7ad845f20fc17cc8088a0d9312b17da1",
		},
		tls.HelloChrome_104.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "7ad845f20fc17cc8088a0d9312b17da1",
		},
		tls.HelloChrome_103.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "7ad845f20fc17cc8088a0d9312b17da1",
		},
	},
	firefox: {
		tls.HelloFirefox_102.Str(): map[string]string{
			ja3String:             "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
			ja3Hash:               "579ccef312d18482fc42e2b822ca2430",
			akamaiFingerprint:     "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
			akamaiFingerprintHash: "fd4f649c50a64e33cc9e2407055bafbe",
		},
		tls.HelloFirefox_104.Str(): map[string]string{
			ja3String:             "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
			ja3Hash:               "579ccef312d18482fc42e2b822ca2430",
			akamaiFingerprint:     "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
			akamaiFingerprintHash: "fd4f649c50a64e33cc9e2407055bafbe",
		},
		tls.HelloFirefox_105.Str(): map[string]string{
			ja3String:             "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
			ja3Hash:               "579ccef312d18482fc42e2b822ca2430",
			akamaiFingerprint:     "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
			akamaiFingerprintHash: "fd4f649c50a64e33cc9e2407055bafbe",
		},
		tls.HelloFirefox_106.Str(): map[string]string{
			ja3String:             "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
			ja3Hash:               "579ccef312d18482fc42e2b822ca2430",
			akamaiFingerprint:     "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
			akamaiFingerprintHash: "fd4f649c50a64e33cc9e2407055bafbe",
		},
		tls.HelloFirefox_108.Str(): map[string]string{
			ja3String:             "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
			ja3Hash:               "579ccef312d18482fc42e2b822ca2430",
			akamaiFingerprint:     "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
			akamaiFingerprintHash: "fd4f649c50a64e33cc9e2407055bafbe",
		},
		tls.HelloFirefox_110.Str(): map[string]string{
			ja3String:             "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-21,29-23-24-25-256-257,0",
			ja3Hash:               "ad55557b7cbd735c2627f7ebb3b3d493",
			akamaiFingerprint:     "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
			akamaiFingerprintHash: "fd4f649c50a64e33cc9e2407055bafbe",
		},
	},
	opera: {
		tls.HelloOpera_89.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "7ad845f20fc17cc8088a0d9312b17da1",
		},
		tls.HelloOpera_90.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "7ad845f20fc17cc8088a0d9312b17da1",
		},
		tls.HelloOpera_91.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			ja3Hash:               "cd08e31494f9531f560d64c695473da9",
			akamaiFingerprint:     "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
			akamaiFingerprintHash: "7ad845f20fc17cc8088a0d9312b17da1",
		},
	},
	safari: {
		tls.HelloSafari_15_6_1.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
			ja3Hash:               "773906b0efdefa24a7f2b8eb6985bf37",
			akamaiFingerprint:     "4:4194304,3:100|10485760|0|m,s,p,a",
			akamaiFingerprintHash: "e7b6dfd2eca81022e22f49765591e8c3",
		},
		tls.HelloSafari_16_0.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
			ja3Hash:               "773906b0efdefa24a7f2b8eb6985bf37",
			akamaiFingerprint:     "4:4194304,3:100|10485760|0|m,s,p,a",
			akamaiFingerprintHash: "e7b6dfd2eca81022e22f49765591e8c3",
		},
	},
	safariIpadOs: {
		tls.HelloIPad_15_6.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
			ja3Hash:               "773906b0efdefa24a7f2b8eb6985bf37",
			akamaiFingerprint:     "4:2097152,3:100|10485760|0|m,s,p,a",
			akamaiFingerprintHash: "8fe3e4ae51fb38d5c5108eabbf2a123c",
		},
	},
	safariIos: {
		tls.HelloIOS_15_5.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
			ja3Hash:               "773906b0efdefa24a7f2b8eb6985bf37",
			akamaiFingerprint:     "4:2097152,3:100|10485760|0|m,s,p,a",
			akamaiFingerprintHash: "8fe3e4ae51fb38d5c5108eabbf2a123c",
		},
		tls.HelloIOS_15_6.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
			ja3Hash:               "773906b0efdefa24a7f2b8eb6985bf37",
			akamaiFingerprint:     "4:2097152,3:100|10485760|0|m,s,p,a",
			akamaiFingerprintHash: "8fe3e4ae51fb38d5c5108eabbf2a123c",
		},
		tls.HelloIOS_16_0.Str(): map[string]string{
			ja3String:             "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
			ja3Hash:               "773906b0efdefa24a7f2b8eb6985bf37",
			akamaiFingerprint:     "4:2097152,3:100|10485760|0|m,s,p,a",
			akamaiFingerprintHash: "8fe3e4ae51fb38d5c5108eabbf2a123c",
		},
	},
	okhttpAndroid: {
		tls_client.Okhttp4Android13.GetClientHelloStr(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
			ja3Hash:               "f79b6bad2ad0641e1921aef10262856b",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
		tls_client.Okhttp4Android12.GetClientHelloStr(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
			ja3Hash:               "f79b6bad2ad0641e1921aef10262856b",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
		tls_client.Okhttp4Android11.GetClientHelloStr(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
			ja3Hash:               "f79b6bad2ad0641e1921aef10262856b",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
		tls_client.Okhttp4Android10.GetClientHelloStr(): map[string]string{
			ja3String:             "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
			ja3Hash:               "f79b6bad2ad0641e1921aef10262856b",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
		tls_client.Okhttp4Android9.GetClientHelloStr(): map[string]string{
			ja3String:             "771,49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,65281-0-23-35-13-5-16-11-10,29-23-24,0",
			ja3Hash:               "6f5e62edfa5933b1332ddf8b9fb3ef9d",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
		tls_client.Okhttp4Android8.GetClientHelloStr(): map[string]string{
			ja3String:             "771,49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,65281-0-23-35-13-5-16-11-10,29-23-24,0",
			ja3Hash:               "6f5e62edfa5933b1332ddf8b9fb3ef9d",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
		tls_client.Okhttp4Android7.GetClientHelloStr(): map[string]string{
			ja3String:             "771,49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,65281-0-23-35-13-16-11-10,23-24-25,0",
			ja3Hash:               "f6a0bfafe2bf7d9c79ffb3f269b64b46",
			akamaiFingerprint:     "4:16777216|16711681|0|m,p,a,s",
			akamaiFingerprintHash: "605a1154008045d7e3cb3c6fb062c0ce",
		},
	},
}
