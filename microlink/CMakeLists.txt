# MicroLink - Tailscale-Compatible VPN for ESP32
# ESP-IDF Component CMakeLists.txt

# Select DISCO implementation based on Kconfig
# Zero-copy mode uses raw lwIP PCB for high-throughput (video streaming)
# Default mode uses BSD sockets for simplicity and portability
if(CONFIG_MICROLINK_ZERO_COPY_WG)
    set(DISCO_SRC "src/microlink_disco_zerocopy.c")
    message(STATUS "MicroLink: Using zero-copy DISCO (raw lwIP PCB) - contributed by dj-oyu")
else()
    set(DISCO_SRC "src/microlink_disco.c")
    message(STATUS "MicroLink: Using standard DISCO (BSD sockets)")
endif()

idf_component_register(
    SRCS
        "src/microlink.c"
        "src/microlink_connection.c"
        "src/microlink_coordination.c"
        "src/microlink_derp.c"
        "${DISCO_SRC}"
        "src/microlink_stun.c"
        "src/microlink_udp.c"
        "src/microlink_wireguard.c"
        "src/nacl_box.c"
        "src/x25519.c"
    INCLUDE_DIRS
        "include"
        "src"
    REQUIRES
        esp_wifi
        esp_netif
        esp_http_client
        mbedtls
        nvs_flash
        esp_timer
        lwip
        wireguard_lwip
        json
)

# Enable optimizations for crypto code
# Disable format warnings for uint32_t format specifiers (ESP-IDF 5.3 uses long unsigned int)
# Disable stringop-overread for x25519.c mul() function (false positive - nb param limits read size)
target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -Wno-format -Wno-stringop-overread)
