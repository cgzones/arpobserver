#include "../src/base64.h"

#include <check.h>
#include <stdlib.h>
#include <time.h>


START_TEST(test_one)
{
	const char *str = "Hello World!";
	const char *encoding = "SGVsbG8gV29ybGQh";
	char encode_buffer[256], decode_buffer[256];
	size_t encode_size, decode_size;

	encode_size = base64_encode(str, strlen(str), encode_buffer, sizeof(encode_buffer));
	ck_assert_uint_eq(encode_size, strlen(encoding));
	ck_assert_mem_eq(encode_buffer, encoding, encode_size);

	decode_size = base64_decode(encode_buffer, encode_size, decode_buffer, sizeof(decode_buffer));
	ck_assert_uint_eq(decode_size, strlen(str));
	ck_assert_mem_eq(decode_buffer, str, decode_size);
}
END_TEST


START_TEST(test_two)
{
	const char *str = "Hello World!";
	const char *encoding = "SGVsbG8gV29ybGQhAA==";
	char encode_buffer[256], decode_buffer[256];
	size_t encode_size, decode_size;

	encode_size = base64_encode(str, strlen(str) + 1, encode_buffer, sizeof(encode_buffer));
	ck_assert_uint_eq(encode_size, strlen(encoding));
	ck_assert_mem_eq(encode_buffer, encoding, encode_size);

	decode_size = base64_decode(encode_buffer, encode_size, decode_buffer, sizeof(decode_buffer));
	ck_assert_uint_eq(decode_size, strlen(str) + 1);
	ck_assert_mem_eq(decode_buffer, str, decode_size);
	ck_assert_int_eq(str[strlen(str)], '\0');
	ck_assert_int_eq(decode_buffer[strlen(str)], '\0');
	ck_assert_mem_eq(decode_buffer, str, strlen(str) + 1);
}
END_TEST


START_TEST(test_two_pad1)
{
	const char *str = "Hello World";
	const char *encoding = "SGVsbG8gV29ybGQ=";
	char encode_buffer[256], decode_buffer[256];
	size_t encode_size, decode_size;

	encode_size = base64_encode(str, strlen(str), encode_buffer, sizeof(encode_buffer));
	ck_assert_uint_eq(encode_size, strlen(encoding));
	ck_assert_mem_eq(encode_buffer, encoding, encode_size);

	decode_size = base64_decode(encode_buffer, encode_size, decode_buffer, sizeof(decode_buffer));
	ck_assert_uint_eq(decode_size, strlen(str));
	ck_assert_mem_eq(decode_buffer, str, decode_size);
}
END_TEST


START_TEST(test_two_pad2)
{
	const char *str = "Hello Worl";
	const char *encoding = "SGVsbG8gV29ybA==";
	char encode_buffer[256], decode_buffer[256];
	size_t encode_size, decode_size;

	encode_size = base64_encode(str, strlen(str), encode_buffer, sizeof(encode_buffer));
	ck_assert_uint_eq(encode_size, strlen(encoding));
	ck_assert_mem_eq(encode_buffer, encoding, encode_size);

	decode_size = base64_decode(encode_buffer, encode_size, decode_buffer, sizeof(decode_buffer));
	ck_assert_uint_eq(decode_size, strlen(str));
	ck_assert_mem_eq(decode_buffer, str, decode_size);
}
END_TEST


START_TEST(test_three)
{
	const char *str = "The quick\nbrown fox\njumps over\nthe lazy\tdog!!";
	const char *encoding = "VGhlIHF1aWNrCmJyb3duIGZveApqdW1wcyBvdmVyCnRoZSBsYXp5CWRvZyEhAA==";
	char encode_buffer[256], decode_buffer[256];
	size_t encode_size, decode_size;

	encode_size = base64_encode(str, strlen(str) + 1, encode_buffer, sizeof(encode_buffer));
	ck_assert_uint_eq(encode_size, strlen(encoding));
	ck_assert_mem_eq(encode_buffer, encoding, encode_size);

	decode_size = base64_decode(encode_buffer, encode_size, decode_buffer, sizeof(decode_buffer));
	ck_assert_uint_eq(decode_size, strlen(str) + 1);
	ck_assert_mem_eq(decode_buffer, str, decode_size);
	ck_assert_int_eq(str[strlen(str)], '\0');
	ck_assert_int_eq(decode_buffer[strlen(str)], '\0');
	ck_assert_mem_eq(decode_buffer, str, strlen(str) + 1);
}
END_TEST

START_TEST(test_random)
{
	const size_t rounds = 100000;
#define MAX_DATA_SIZE 400

	unsigned char data[MAX_DATA_SIZE];
	char encode_buffer[1024], decode_buffer[MAX_DATA_SIZE];
	char encode_check_buffer[1024], decode_check_buffer[1024];

	memset(encode_check_buffer, 23, sizeof(encode_check_buffer));
	memset(decode_check_buffer, 24, sizeof(decode_check_buffer));
	srand((unsigned)time(NULL));

	for (size_t i = 0; i < rounds; ++i) {
		size_t data_size;
		size_t encode_size, decode_size;

		memset(encode_buffer, 23, sizeof(encode_buffer));
		memset(decode_buffer, 24, sizeof(decode_buffer));

		data_size = (unsigned)rand() % (MAX_DATA_SIZE - 1) + 1;
		ck_assert_uint_gt(data_size, 0);
		ck_assert_uint_le(data_size, MAX_DATA_SIZE);

		for (size_t j = 0; j < data_size; j++)
			data[j] = (uint8_t)((unsigned)rand() % 256);

		encode_size = base64_encode(data, data_size, encode_buffer, sizeof(encode_buffer));
		ck_assert_uint_gt(encode_size, 0);
		ck_assert_uint_ge(encode_size, data_size);
		ck_assert_uint_le(encode_size, sizeof(encode_buffer));
		ck_assert_mem_eq(encode_buffer + encode_size, encode_check_buffer, sizeof(encode_buffer) - encode_size);

		decode_size = base64_decode(encode_buffer, encode_size, decode_buffer, sizeof(decode_buffer));
		ck_assert_uint_eq(decode_size, data_size);
		ck_assert_mem_eq(decode_buffer, data, data_size);
		ck_assert_mem_eq(decode_buffer + decode_size, decode_check_buffer, sizeof(decode_buffer) - decode_size);
	}
}
END_TEST


static Suite *base64_suite(void)
{
	Suite *s;
	TCase *tc_core, *tc_rnd;

	s = suite_create("base64");
	tc_core = tcase_create("Core");
	tc_rnd = tcase_create("Random");
	tcase_set_timeout(tc_rnd, 60);

	tcase_add_test(tc_core, test_one);
	tcase_add_test(tc_core, test_two);
	tcase_add_test(tc_core, test_two_pad1);
	tcase_add_test(tc_core, test_two_pad2);
	tcase_add_test(tc_core, test_three);

	tcase_add_test(tc_rnd, test_random);

	suite_add_tcase(s, tc_core);
	suite_add_tcase(s, tc_rnd);

	return s;
}

int main(void)
{
	int no_failed = 0;

	Suite *s;
	SRunner *runner;

	s = base64_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_NORMAL);

	no_failed = srunner_ntests_failed(runner);

	srunner_free(runner);

	return no_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
