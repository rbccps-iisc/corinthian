#ifndef __H_KORE_ASSETS_H
#define __H_KORE_ASSETS_H
extern const u_int8_t asset_ui_html[];
extern const u_int32_t asset_len_ui_html;
extern const time_t asset_mtime_ui_html;
extern const char *asset_sha256_ui_html;
int asset_serve_ui_html(struct http_request *);
extern const u_int8_t asset_home_html[];
extern const u_int32_t asset_len_home_html;
extern const time_t asset_mtime_home_html;
extern const char *asset_sha256_home_html;
int asset_serve_home_html(struct http_request *);

#endif
