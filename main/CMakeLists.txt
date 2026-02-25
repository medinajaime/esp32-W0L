idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES tailscale nvs_flash esp_wifi esp_netif esp_event esp_timer
)
