package tls_client

import (
	"fmt"
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
	ran "math/rand"
	"time"
)

var DefaultClientProfile = Chrome_112

var MappedTLSClients = map[string]ClientProfile{
	"chrome_103":       Chrome_103,
	"chrome_104":       Chrome_104,
	"chrome_105":       Chrome_105,
	"chrome_106":       Chrome_106,
	"chrome_107":       Chrome_107,
	"chrome_108":       Chrome_108,
	"chrome_109":       Chrome_109,
	"chrome_110":       Chrome_110,
	"chrome_111":       Chrome_111,
	"chrome_112":       Chrome_112,
	"safari_15_6_1":    Safari_15_6_1,
	"safari_16_0":      Safari_16_0,
	"safari_ipad_15_6": Safari_Ipad_15_6,
	"safari_ios_15_5":  Safari_IOS_15_5,
	"safari_ios_15_6":  Safari_IOS_15_6,
	"safari_ios_16_0":  Safari_IOS_16_0,
	"firefox_102":      Firefox_102,
	"firefox_104":      Firefox_104,
	"firefox_105":      Firefox_105,
	"firefox_106":      Firefox_106,
	"firefox_108":      Firefox_108,
	"firefox_110":      Firefox_110,
	"opera_89":         Opera_89,
	"opera_90":         Opera_90,
	"opera_91":         Opera_91,
}

type ClientProfile struct {
	clientHelloId     tls.ClientHelloID
	connectionFlow    uint32
	headerPriority    *http2.PriorityParam
	priorities        []http2.Priority
	pseudoHeaderOrder []string
	settings          map[http2.SettingID]uint32
	settingsOrder     []http2.SettingID
}

var (
	random = ran.New(ran.NewSource(time.Now().UnixNano()))
)

func NewClientProfile(clientHelloId tls.ClientHelloID, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, pseudoHeaderOrder []string, connectionFlow uint32, priorities []http2.Priority, headerPriority *http2.PriorityParam) ClientProfile {
	return ClientProfile{
		clientHelloId:     clientHelloId,
		settings:          settings,
		settingsOrder:     settingsOrder,
		pseudoHeaderOrder: pseudoHeaderOrder,
		connectionFlow:    connectionFlow,
		priorities:        priorities,
		headerPriority:    headerPriority,
	}
}

func (c ClientProfile) GetClientHelloSpec() (tls.ClientHelloSpec, error) {
	return c.clientHelloId.ToSpec()
}

func (c ClientProfile) GetClientHelloStr() string {
	return c.clientHelloId.Str()
}

func GetRandomFirefoxClientHelloID(version string) tls.ClientHelloID {
	return tls.ClientHelloID{"Firefox", false, version, nil, tls.EmptyClientHelloSpecFactory}
}
func GetRandomChromeClientHelloID(version string) tls.ClientHelloID {
	return tls.ClientHelloID{"Chrome", false, version, nil, tls.EmptyClientHelloSpecFactory}
}

func GetRandomNumber(betweenthis, andthat int) int {
	return rand().Intn(andthat-betweenthis+1) + betweenthis
}

func ShuffleStrings(strings []string) {
	r := rand()
	n := len(strings)
	for i := n - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		strings[i], strings[j] = strings[j], strings[i]
	}
}

func ShuffleSubset(arr []uint16, subsetSize int) []uint16 {

	n := len(arr)
	if subsetSize >= n {
		return arr // Return the entire array if the subset size is equal or larger
	}

	// Create a copy of the original array
	shuffledArr := make([]uint16, n)
	copy(shuffledArr, arr)

	r := rand()

	// Shuffle the first 'subsetSize' elements
	for i := 0; i < subsetSize; i++ {
		j := r.Intn(n - i)
		shuffledArr[i], shuffledArr[i+j] = shuffledArr[i+j], shuffledArr[i]
	}

	// Return the first 'subsetSize' elements as the shuffled subset
	return shuffledArr[:subsetSize]
}

func ShuffleSubsetCurve(arr []tls.CurveID, subsetSize int) []tls.CurveID {

	n := len(arr)
	if subsetSize >= n {
		return arr // Return the entire array if the subset size is equal or larger
	}

	// Create a copy of the original array
	shuffledArr := make([]tls.CurveID, n)
	copy(shuffledArr, arr)

	r := rand()

	// Shuffle the first 'subsetSize' elements
	for i := 0; i < subsetSize; i++ {
		j := r.Intn(n - i)
		shuffledArr[i], shuffledArr[i+j] = shuffledArr[i+j], shuffledArr[i]
	}

	// Return the first 'subsetSize' elements as the shuffled subset
	return shuffledArr[:subsetSize]
}

func ShuffleSubsetSignatureSchemes(arr []tls.SignatureScheme, subsetSize int) []tls.SignatureScheme {

	n := len(arr)
	if subsetSize >= n {
		return arr // Return the entire array if the subset size is equal or larger
	}

	// Create a copy of the original array
	shuffledArr := make([]tls.SignatureScheme, n)
	copy(shuffledArr, arr)

	r := rand()

	// Shuffle the first 'subsetSize' elements
	for i := 0; i < subsetSize; i++ {
		j := r.Intn(n - i)
		shuffledArr[i], shuffledArr[i+j] = shuffledArr[i+j], shuffledArr[i]
	}

	// Return the first 'subsetSize' elements as the shuffled subset
	return shuffledArr[:subsetSize]
}

// Custom random number generator using time as a seed.
func rand() *randGen {
	return &randGen{seed: time.Now().UnixNano()}
}

type randGen struct {
	seed int64
}

func (r *randGen) Intn(n int) int {
	r.seed = (r.seed*6364136223846793005 + 1) & 0x7fffffffffffffff
	return int(r.seed % int64(n))
}

func BuildRandomClient() ClientProfile {

	allCipherSuites := []uint16{
		/*
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		*/

		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	ciphers := ShuffleSubset(allCipherSuites, GetRandomNumber(12, 16))

	curves := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.FAKEFFDHE2048,
		tls.FAKEFFDHE3072,
	}
	curves = ShuffleSubsetCurve(curves, GetRandomNumber(4, 6))

	signatureSchemes := []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512,
		tls.PSSWithSHA256,
		tls.PSSWithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA256,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA512,
		tls.ECDSAWithSHA1,
		tls.PKCS1WithSHA1,
	}
	signatureSchemes = ShuffleSubsetSignatureSchemes(signatureSchemes, GetRandomNumber(6, 10))

	pseudoHeaderOrder := []string{":method", ":path", ":authority", ":scheme"}
	ShuffleStrings(pseudoHeaderOrder)

	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "krmvkrmb",
			RandomExtensionOrder: true,
			Version:              "542",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: ciphers,
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{curves},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},

						&tls.SessionTicketExtension{},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: signatureSchemes},
						&tls.PSKKeyExchangeModesExtension{[]uint8{
							tls.PskModeDHE,
						}},
						&tls.FakeRecordSizeLimitExtension{0x4001},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536 * uint32(GetRandomNumber(1, 8)),
			http2.SettingInitialWindowSize: 131072 * uint32(GetRandomNumber(1, 8)),
			http2.SettingMaxFrameSize:      16384 * uint32(GetRandomNumber(1, 8)),
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: pseudoHeaderOrder,
		connectionFlow:    12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

func BuildEdge101() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Edge",
			RandomExtensionOrder: true,
			Version:              "114",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				extensions := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						0x00, // pointFormatUncompressed
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}

				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						0x00, // compressionNone
					},
					Extensions: extensions,
				}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 15663105,
		headerPriority: &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

func BuildSafari15() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Safari",
			RandomExtensionOrder: true,
			Version:              "15",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				extensions := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						0x00, // pointFormatUncompressed
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}

				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						0x00, // compressionNone
					},
					Extensions: extensions,
				}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			//http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 4194304,
			//http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 100,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

func BuildChrome119() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Chrome",
			RandomExtensionOrder: true,
			Version:              "119",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				extensions := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519, tls.CurveP256, tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						0x00, // pointFormatUncompressed
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.GenericExtension{Id: 0x002b}, // placeholder for GREASE
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}

				// Randomly shuffle the extensions if required
				shuffleTLSExtensions(extensions[1 : len(extensions)-1])

				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						0x00, // compressionNone
					},
					Extensions: extensions,
				}, nil
			},
		},
	}
}

// shuffleTLSExtensions shuffles the slice of TLS extensions
func shuffleTLSExtensions(extensions []tls.TLSExtension) {
	ran.Seed(time.Now().UnixNano())
	ran.Shuffle(len(extensions), func(i, j int) {
		extensions[i], extensions[j] = extensions[j], extensions[i]
	})
}

func BuildChrome117() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Chrome",
			RandomExtensionOrder: true,
			Version:              "117",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				extensions := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SNIExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.SCTExtension{},
					&tls.StatusRequestExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						0x00, // pointFormatUncompressed
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}

				shuffleTLSExtensions(extensions[1 : len(extensions)-1])

				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						0x00, // compressionNone
					},
					Extensions: extensions,
				}, nil
			},
		},
	}
}

func BuildBumbleFirefox119() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              "119",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{[]tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
						&tls.FakeRecordSizeLimitExtension{0x4001},
						&tls.PreSharedKeyExtension{},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

}

//Missing ECH extension support

func BuildBumbleFirefox118() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              "118",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{[]tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						}},

						&tls.FakeRecordSizeLimitExtension{0x4001},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

}

//Missing ECH extension support

func BuildBumbleFirefox117Client() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              "117",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{[]tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},

						&tls.SessionTicketExtension{},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						}},
						&tls.PSKKeyExchangeModesExtension{[]uint8{
							tls.PskModeDHE,
						}},
						&tls.FakeRecordSizeLimitExtension{0x4001},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

//Missing ACK flag on frames settings direct support (possible & factible addition)

func BuildBumbleFirefox116() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              "116",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{[]tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						}},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
						&tls.FakeRecordSizeLimitExtension{0x4001},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

}

func BuildBumbleFirefox108() ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              "",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{[]tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						}},
						&tls.FakeRecordSizeLimitExtension{0x4001},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

func BuildBumbleFirefoxRandomClient(firefoxversion string) ClientProfile {

	return ClientProfile{
		clientHelloId: GetRandomFirefoxClientHelloID(firefoxversion),
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

func BuildBumbleChromeRandomClient(version string) ClientProfile {
	return ClientProfile{
		clientHelloId: GetRandomChromeClientHelloID(version),
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},

		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		connectionFlow: 15663105,
	}

}

func BuildBumbleFirefoxClient() ClientProfile {

	seed, _ := tls.NewPRNGSeed()

	fmt.Printf("Random Seed: %x\n", *seed)

	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              "117",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{[]tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},

						&tls.SessionTicketExtension{},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.DelegatedCredentialsExtension{
							AlgorithmsSignature: []tls.SignatureScheme{
								tls.ECDSAWithP256AndSHA256,
								tls.ECDSAWithP384AndSHA384,
								tls.ECDSAWithP521AndSHA512,
								tls.ECDSAWithSHA1,
							},
						},
						&tls.KeyShareExtension{[]tls.KeyShare{
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						}},
						&tls.SupportedVersionsExtension{[]uint16{
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						}},
						&tls.PSKKeyExchangeModesExtension{[]uint8{
							tls.PskModeDHE,
						}},
						&tls.FakeRecordSizeLimitExtension{0x4001},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					}}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

func BuildBumbleClientWithRandomALPN() ClientProfile {

	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Randomized-ALPN",
			RandomExtensionOrder: false,
			Version:              "",
			Seed:                 nil,
			SpecFactory:          tls.EmptyClientHelloSpecFactory,
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		connectionFlow: 12517377,
		headerPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}
}

var Chrome_112 = ClientProfile{
	clientHelloId: tls.HelloChrome_112,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_111 = ClientProfile{
	clientHelloId: tls.HelloChrome_111,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_110 = ClientProfile{
	clientHelloId: tls.HelloChrome_110,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_109 = ClientProfile{
	clientHelloId: tls.HelloChrome_109,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_108 = ClientProfile{
	clientHelloId: tls.HelloChrome_108,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_107 = ClientProfile{
	clientHelloId: tls.HelloChrome_107,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_106 = ClientProfile{
	clientHelloId: tls.HelloChrome_106,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_105 = ClientProfile{
	clientHelloId: tls.HelloChrome_105,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_104 = ClientProfile{
	clientHelloId: tls.HelloChrome_104,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Chrome_103 = ClientProfile{
	clientHelloId: tls.HelloChrome_103,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Safari_15_6_1 = ClientProfile{
	clientHelloId: tls.HelloSafari_15_6_1,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    4194304,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}

var Safari_16_0 = ClientProfile{
	clientHelloId: tls.HelloSafari_16_0,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    4194304,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}

var Safari_Ipad_15_6 = ClientProfile{
	clientHelloId: tls.HelloIPad_15_6,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}

var Safari_IOS_16_0 = ClientProfile{
	clientHelloId: tls.HelloIOS_16_0,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}

var Safari_IOS_15_5 = ClientProfile{
	clientHelloId: tls.HelloIOS_15_5,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}

var Safari_IOS_15_6 = ClientProfile{
	clientHelloId: tls.HelloIOS_15_6,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}

var Firefox_110 = ClientProfile{
	clientHelloId: tls.HelloFirefox_110,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_108 = ClientProfile{
	clientHelloId: tls.HelloFirefox_108,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_106 = ClientProfile{
	clientHelloId: tls.HelloFirefox_106,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_105 = ClientProfile{
	clientHelloId: tls.HelloFirefox_105,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_104 = ClientProfile{
	clientHelloId: tls.HelloFirefox_104,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_102 = ClientProfile{
	clientHelloId: tls.HelloFirefox_102,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Opera_90 = ClientProfile{
	clientHelloId: tls.HelloOpera_90,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Opera_91 = ClientProfile{
	clientHelloId: tls.HelloOpera_91,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}

var Opera_89 = ClientProfile{
	clientHelloId: tls.HelloOpera_89,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
