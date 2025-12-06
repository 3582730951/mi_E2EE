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
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        [ "OS=='win'", {
          "libraries": [
            "<(module_root_dir)/../../build/mi_client_E2EE/Release/mi_client_e2ee.lib",
            "<(module_root_dir)/../../build/Release/mi_internal.lib",
            "ws2_32.lib"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": { "ExceptionHandling": 0, "RuntimeLibrary": 2 }
          }
        }],
        [ "OS!='win'", {
          "library_dirs": [
            "<(module_root_dir)/../../build/mi_client_E2EE",
            "<(module_root_dir)/../../build"
          ],
          "libraries": [
            "-lmi_client_e2ee"
          ],
          "link_settings": {
            "library_dirs": [
              "<(module_root_dir)/../../build/mi_client_E2EE",
              "<(module_root_dir)/../../build"
            ]
          }
        }]
      ]
    }
  ]
}
