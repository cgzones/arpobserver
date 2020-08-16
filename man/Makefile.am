MAN_PAGES = arpobserverd.8 arpobserver-checkd.8
EXTRA_DIST = arpobserverd.8.adoc arpobserver-checkd.8.adoc footer.adoc.template

dist_man_MANS = $(MAN_PAGES)

CLEANFILES = $(MAN_PAGES)

arpobserverd.8: arpobserverd.8.adoc footer.adoc.template
	asciidoctor --backend manpage --doctype manpage --verbose --warnings --failure-level WARN $<

arpobserver-checkd.8: arpobserver-checkd.8.adoc footer.adoc.template
	asciidoctor --backend manpage --doctype manpage --verbose --warnings --failure-level WARN $<
