#include <check.h>
#include <protocol_string.h>
#include <stdlib.h>
#include <varint.h>

START_TEST(test_string_create) {
    PROTOCOL_STRING string = protocol_string_from_c_string("Testing");

    ck_assert_uint_eq(string.size, 8);
    ck_assert_int_eq(strncmp(string.text, "Testing", 7), 0);
    ck_assert_int_eq(varint_to_int(&string.length), 7);

    protocol_string_free(&string);
}
END_TEST

static Suite* protocol_string_suite() {
    Suite* suite;
    TCase* tc_core;

    suite = suite_create("protocol_string");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_string_create);
    suite_add_tcase(suite, tc_core);

    return suite;
}

int main() {
    int number_failed;
    Suite* suite;
    SRunner* suite_runner;

    suite = protocol_string_suite();
    suite_runner = srunner_create(suite);

    srunner_run_all(suite_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(suite_runner);
    srunner_free(suite_runner);
    if (number_failed != 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}