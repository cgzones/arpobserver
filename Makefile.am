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
