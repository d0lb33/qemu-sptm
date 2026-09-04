#include "qemu/osdep.h"
#include "xnu/darwin_afk_state.h"

static void captured_requests(void)
{
    /* DISPLAY_PROTOCOL_R1, ep 0x20: open seq 17, close seq 18. */
    const uint8_t requests[][12] = {
        {17, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0},
        {18, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0},
    };
    const uint8_t expected[][12] = {
        {17, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0},
        {18, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0},
    };
    uint8_t reply[12];

    for (size_t i = 0; i < G_N_ELEMENTS(requests); i++) {
        g_assert_true(darwin_afk_build_state_ack(0, 0, requests[i], 12, reply));
        g_assert_cmpmem(reply, 12, expected[i], 12);
        /* Acknowledgements must not cause an acknowledgement loop. */
        g_assert_false(darwin_afk_build_state_ack(0, 0, expected[i], 12, reply));
    }
}

static void reject_other_frames(void)
{
    uint8_t request[13] = {0xff, 0xff, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0};
    uint8_t reply[12];

    g_assert_true(darwin_afk_build_state_ack(0, 0, request, 12, reply));
    g_assert_cmpuint(lduw_le_p(reply), ==, 0xffff);
    for (uint32_t len = 0; len < sizeof(request); len++) {
        if (len != 12) {
            g_assert_false(darwin_afk_build_state_ack(0, 0, request, len, reply));
        }
    }
    g_assert_false(darwin_afk_build_state_ack(0, 0, request, 13, reply));
    g_assert_false(darwin_afk_build_state_ack(1, 0, request, 12, reply));
    g_assert_false(darwin_afk_build_state_ack(0, 3, request, 12, reply));
    const size_t fixed[] = {2, 3, 4, 5, 6, 7, 9, 10, 11};
    for (size_t i = 0; i < G_N_ELEMENTS(fixed); i++) {
        request[fixed[i]] ^= 1;
        g_assert_false(darwin_afk_build_state_ack(0, 0, request, 12, reply));
        request[fixed[i]] ^= 1;
    }
    request[8] = 1;
    g_assert_false(darwin_afk_build_state_ack(0, 0, request, 12, reply));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/darwin-afk-state/captured-requests", captured_requests);
    g_test_add_func("/darwin-afk-state/reject-other-frames", reject_other_frames);
    return g_test_run();
}
