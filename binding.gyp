{
  "targets": [{
    "target_name": "secp256k1",
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "xcode_settings": { "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.7",
      },
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 },
      },
    "variables": {
      "conditions": [
        [
          "OS=='win'", {
            "with_gmp%": "false"
          }, {
            "with_gmp%": "<!(scripts/checklib gmpxx && scripts/checklib gmp)"
          }
        ]
      ]
    },
    "sources": [
      "./native/addon.cpp",
      "./native/secp256k1/src/secp256k1.c"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "/usr/local/include",
      "./native/secp256k1",
      "./native/secp256k1/contrib",
      "./native/secp256k1/include",
      "./native/secp256k1/src",
    ],
    "defines": [
      "ECMULT_GEN_PREC_BITS=4",
      "ECMULT_WINDOW_SIZE=15",
    ],
    "cflags": [
      "-Wall",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra"
    ],
    "cflags_cc+": [
      "-std=c++11"
    ],
    "conditions": [
      [
        "with_gmp=='true'", {
          "defines": [
            "HAVE_LIBGMP=1",
            "USE_NUM_GMP=1",
            "USE_FIELD_INV_NUM=1",
            "USE_SCALAR_INV_NUM=1"
          ],
          "libraries": [
            "-lgmpxx",
            "-lgmp"
          ]
        }, {
          "defines": [
            "USE_NUM_NONE=1",
            "USE_FIELD_INV_BUILTIN=1",
            "USE_SCALAR_INV_BUILTIN=1"
          ]
        }
      ],
      [
        "target_arch=='x64' and OS!='win'", {
          "defines": [
            "HAVE___INT128=1",
            "USE_ASM_X86_64=1",
            "USE_FIELD_5X52=1",
            "USE_FIELD_5X52_INT128=1",
            "USE_SCALAR_4X64=1"
          ]
        }, {
          "defines": [
            "USE_FIELD_10X26=1",
            "USE_SCALAR_8X32=1"
          ]
        }
      ],
      [
        "OS=='mac'", {
          "libraries": [
            "-L/usr/local/lib"
          ],
          "xcode_settings": {
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "OTHER_CPLUSPLUSFLAGS": [
              "-stdlib=libc++"
            ]
          }
        }
      ]
    ]
  }]
}
