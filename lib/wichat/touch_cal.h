/* WiChat touch stub — uses SquatchWatch's touch driver */
#ifndef WICHAT_TOUCH_CAL_H
#define WICHAT_TOUCH_CAL_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void touch_init(void);
bool touch_read(int16_t *x, int16_t *y);
#ifdef __cplusplus
}
#endif
#endif
