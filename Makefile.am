SUBDIRS = conf src

if ENABLE_MAN
SUBDIRS += man
endif

if WITH_CHECK
SUBDIRS += tests
else
check-local:
	@echo "Configured without Check support!!"
	@exit 1
endif

apply-codespell:
	codespell -C2 -Lnd,objext --skip .git,config.log,depcomp,aclocal.m4,arpobserverd.8,arpobserver-checkd.8 -q 2

apply-format:
	clang-format-11 -i --Werror src/*.c src/*.h tests/*.c
