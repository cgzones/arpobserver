project('arpobserver', 'c',
        version : '0.1',
        license : 'GPL-3.0',
        default_options: [
           'c_std=gnu99',
           'prefix=/usr',
           'sysconfdir=/etc',
           'localstatedir=/var',
           'warning_level=2',
        ],
)


cc = meson.get_compiler('c')

required_headers = [
    'arpa/inet.h',
    'net/ethernet.h',
    'net/if.h',
    'netinet/icmp6.h',
    'netinet/if_ether.h',
    'netinet/in.h',
    'netinet/ip6.h',
    'sys/file.h',
    'sys/mman.h',
    'sys/socket.h',
    'sys/stat.h',
    'sys/types.h',
    'syslog.h',
    'unistd.h',
]

foreach h : required_headers
    cc.has_header(h, required : true)
endforeach


dep_check  = dependency('check', version : '>= 0.11', required : false)
dep_event  = dependency('libevent', version : '>= 2.1.8')
dep_mysql  = dependency('mysqlclient', required : false)
dep_pcap   = dependency('pcap', version : '>= 0.9.8')
dep_sqlite = dependency('sqlite3', version : '>= 3.5.9', required : false)

dep_rt     = cc.find_library('rt', required : false)  # shm_open(3)


compiler_arguments = [
    '-Wcast-qual',
    '-Wconversion',
    '-Wdeclaration-after-statement',
    '-Wfloat-equal',
    '-Wformat=2',
    '-Winit-self',
    '-Wmissing-format-attribute',
    '-Wmissing-noreturn',
    '-Wmissing-prototypes',
    '-Wpointer-arith',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wundef',
    '-Wunused',
    '-Wwrite-strings',
]

add_project_arguments(cc.get_supported_arguments(compiler_arguments), language : 'c')


conf_data = configuration_data()

conf_data.set_quoted('PACKAGE', meson.project_name(), description : 'Project name')
conf_data.set_quoted('VERSION', meson.project_version(), description : 'Project version')
conf_data.set_quoted('LOCALSTATEDIR', get_option('localstatedir'), description : 'Localstate data directory')
conf_data.set_quoted('SYSCONFDIR', get_option('sysconfdir'), description : 'Sysconf data directory')
conf_data.set10('HAVE_LIBSQLITE3', dep_sqlite.found(), description : 'Set if sqlite3 is available')

configure_file(#input : 'config.h.in',
               output : 'config.h',
               configuration : conf_data)


install_data([ 'conf/check.conf', 'conf/main.conf' ], install_dir : get_option('sysconfdir') / meson.project_name())


asciidoc = find_program('asciidoctor', required: false)
if asciidoc.found()
    man_pages = [
      'arpobserverd.8',
      'arpobserver-checkd.8',
    ]

    foreach m : man_pages
        custom_target(
            m.underscorify(),
            input: [
              'man' / m + '.adoc',
              'man/footer.adoc.template',
            ],
            output: m,
            command: [
              asciidoc,
              '--backend',
              'manpage',
              '--doctype',
              'manpage',
              #'--verbose',
              '--warnings',
              '--failure-level',
              'WARN',
              '-o',
              '@OUTPUT@',
              '@INPUT0@'
            ],
            install: true,
            install_dir: get_option('mandir') / 'man8',
        )

    endforeach
endif


executable('arpobserverd',
    [
     'src/arpobserverd.c',
     'src/base64.c',
     'src/check_packet.c',
     'src/common.c',
     'src/configfile.c',
     'src/daemonize.c',
     'src/log.c',
     'src/mcache.c',
     'src/output_flatfile.c',
     'src/output_shm.c',
     'src/output_sqlite.c',
     'src/parse.c',
     'src/process.c',
     'src/storage.c',
     'src/util.c',
    ],
    dependencies : [ dep_event, dep_pcap, dep_rt, dep_sqlite ],
    install: true,
    install_dir: get_option('bindir'),
)

executable('arpobserver-checkd',
    [
     'src/arpobserver-checkd.c',
     'src/common.c',
     'src/configfile.c',
     'src/dllist.c',
     'src/log.c',
     'src/protect.c',
     'src/shm_client.c',
     'src/statefile.c',
     'src/util.c',
    ],
    dependencies : dep_rt,
    install: true,
    install_dir: get_option('bindir'),
)

executable('arpobserver-dumpstate',
    [
     'src/arpobserver-dumpstate.c',
     'src/common.c',
     'src/dllist.c',
     'src/log.c',
     'src/statefile.c',
     'src/util.c',
    ],
    install: true,
    install_dir: get_option('bindir'),
)

executable('arpobserver-stdout',
    [
     'src/arpobserver-stdout.c',
     'src/common.c',
     'src/log.c',
     'src/shm_client.c',
    ],
    dependencies : dep_rt,
    install: true,
    install_dir: get_option('bindir'),
)

executable('arpobserver-syslog',
    [
     'src/arpobserver-syslog.c',
     'src/common.c',
     'src/log.c',
     'src/shm_client.c',
    ],
    dependencies : dep_rt,
    install: true,
    install_dir: get_option('bindir'),
)

if dep_mysql.found()
    executable('arpobserver-mysql',
        [
         'src/arpobserver-mysql.c',
         'src/common.c',
         'src/daemonize.c',
         'src/log.c',
         'src/shm_client.c',
        ],
        dependencies : [ dep_mysql, dep_rt ],
        install: true,
        install_dir: get_option('bindir'),
    )
endif


if dep_check.found()
    base64 = executable(
        'check_base64',
        sources : [
          'src/base64.c',
          'tests/check_base64.c',
        ],
        dependencies : dep_check)

    dllist = executable(
        'check_dllist',
        sources : [
          'src/dllist.c',
          'tests/check_dllist.c',
        ],
        dependencies : dep_check)

    test('Test base64 functions', base64)
    test('Test dllist functions', dllist)
endif
