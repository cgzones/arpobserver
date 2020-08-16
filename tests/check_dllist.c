#include <check.h>
#include <time.h>

#include "../src/dllist.h"


START_TEST(test_minimal)
{
	int dummy;
	struct dllist_head *h = dllist_init(NULL);

	ck_assert_ptr_nonnull(h);
	ck_assert_uint_eq(0, h->size);

	ck_assert_int_eq(0, dllist_push_front(h, &dummy));

	ck_assert_int_eq(0, dllist_push_back(h, &dummy));

	ck_assert_uint_eq(2, h->size);

	dllist_promote_entry(h, h->last);

	ck_assert_ptr_nonnull(dllist_delete_entry(h, h->first));

	ck_assert_ptr_null(dllist_delete_entry(h, h->first));

	ck_assert_uint_eq(0, h->size);

	dllist_free(h);
}
END_TEST


START_TEST(test_random)
{
	const size_t rounds = 1000000;
	size_t max_size = 0, sum_size = 0;
	struct dllist_head *h = dllist_init(free);

	ck_assert_ptr_nonnull(h);
	ck_assert_uint_eq(0, h->size);

	srand((unsigned)time(NULL));

	for (size_t i = 0; i < rounds; ++i) {
		int action = rand() % 5;
		size_t elem_no;
		struct dllist_entry *elem;

		switch (action) {
		case 0:
			ck_assert_int_eq(0, dllist_push_front(h, malloc(sizeof(int))));
			break;
		case 1:
			ck_assert_int_eq(0, dllist_push_back(h, malloc(sizeof(int))));
			break;
		case 2:
			if (h->size == 0) {
				ck_assert_ptr_null(h->first);
				ck_assert_ptr_null(h->last);
				break;
			}

			elem_no = (size_t)rand() % h->size + 1;
			do {
				elem = h->first;
			} while (--elem_no > 1);

			ck_assert_ptr_nonnull(elem);

			dllist_promote_entry(h, elem);
			break;
		case 3:
		case 4:
			if (h->size == 0) {
				ck_assert_ptr_null(h->first);
				ck_assert_ptr_null(h->last);
				break;
			}

			elem_no = (size_t)rand() % h->size + 1;
			do {
				elem = h->first;
			} while (--elem_no > 1);

			ck_assert_ptr_nonnull(elem);

			dllist_delete_entry(h, elem);
			break;
		}

		sum_size += h->size;
		if (h->size > max_size)
			max_size = h->size;
	}

	printf("avg size: %zu   end size: %zu   max size: %zu\n", sum_size/rounds, h->size, max_size);

	dllist_free(h);
}
END_TEST


static Suite *dllist_suite(void)
{
	Suite *s;
	TCase *tc_core, *tc_rnd;

	s = suite_create("dllist");
	tc_core = tcase_create("Core");
	tc_rnd = tcase_create("Random");
	tcase_set_timeout(tc_rnd, 60);

	tcase_add_test(tc_core, test_minimal);

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

	s = dllist_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_NORMAL);

	no_failed = srunner_ntests_failed(runner);

	srunner_free(runner);

	return no_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
