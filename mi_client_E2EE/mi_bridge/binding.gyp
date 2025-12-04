{
  "targets": [
    {
      "target_name": "mi_bridge",
      "sources": [ "src/addon.cpp" ],
      "include_dirs": [
        "<!(node -p \"require('node-addon-api').include\")",
        "../include",
        "../../include",
        "../../common"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        [ "OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": { "ExceptionHandling": 0 }
          }
        }]
      ]
    }
  ]
}
