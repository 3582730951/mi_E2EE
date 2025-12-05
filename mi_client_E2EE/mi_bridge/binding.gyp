{
  "targets": [
    {
      "target_name": "mi_bridge",
      "sources": [ "src/addon.cpp" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "../include",
        "../../include",
        "../../common"
      ],
      "dependencies": [
        "<(module_root_dir)/../mi_client_e2ee.vcxproj",
        "<(module_root_dir)/../build/Release/mi_client_e2ee.lib"
      ],
      "libraries": [
        "<(module_root_dir)/../build/Release/mi_client_e2ee.lib",
        "<(module_root_dir)/../build/Debug/mi_client_e2ee.lib"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        [ "OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": { "ExceptionHandling": 0 }
          }
        }],
        [ "OS!='win'", {
          "libraries": [
            "<(module_root_dir)/../build/libmi_client_e2ee.a",
            "<(module_root_dir)/../build/libmi_client_e2ee.so"
          ]
        }]
      ]
    }
  ]
}
