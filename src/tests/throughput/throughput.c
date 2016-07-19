#include "config.h"
#include "throughput.h"
#include "debug.h"


/* TODO update long options for all */
struct option long_options[] =
    {
        {"randomise", no_argument, 0, 'r'},
        {"port", required_argument, 0, 'p'},
        {"test-port", required_argument, 0, 'P'},
        {"write-size", required_argument, 0, 'z'},
        {"rcvbuf", required_argument, 0, 'i'},
        {"sndbuf", required_argument, 0, 'o'},
        {"nodelay", no_argument, 0, 'N'},
        {"mss", required_argument, 0, 'M'},
        {"sequence", required_argument, 0, 'S'},
        {"disable-web10g", no_argument, 0, 'w'},
        {"help", no_argument, 0, 'h'},
        {"server", no_argument, 0, 's'},
        {"client", required_argument, 0, 'c'},
        {"time", required_argument, 0, 't'},
        {"version", no_argument, 0, 'v'},
        {"interface", required_argument, 0, 'I'},
        {"dscp", required_argument, 0, 'Q'},
        {"interpacketgap", required_argument, 0, 'Z'},
        {"ipv4", required_argument, 0, '4'},
        {"ipv6", required_argument, 0, '6'},
/*      {"c2s-time", required_argument, 0, 'T'},
        {"c2s-packet", required_argument, 0, 'Y'},
        {"s2c-time", required_argument, 0, 't'},
        {"s2c-packet", required_argument, 0, 'y'},
        {"pause", required_argument, 0, 'p'},
        {"new", required_argument, 0, 'N'},*/
        {NULL,0,0,0}
    };



/*
 * This usage statement is based on iperf, we do pretty similar things.
 */
void usage(char *prog) {
    fprintf(stderr, "Usage: %s [-s] [options]\n", prog);
    fprintf(stderr, "\n");

    fprintf(stderr, "Server/Client options:\n");
    fprintf(stderr, "  -p, --port       <port>  port number to listen on/connect to (default %d)\n", DEFAULT_CONTROL_PORT);
    fprintf(stderr, "  -I, --interface  <iface> source interface name\n");
    fprintf(stderr, "  -4, --ipv4       <addr>  source IPv4 address\n");
    fprintf(stderr, "  -6, --ipv6       <addr>  source IPv6 address\n");
    fprintf(stderr, "\n");


    fprintf(stderr, "Server specific options:\n");
    fprintf(stderr, "  -s, --server             run in server mode\n");
    fprintf(stderr, "\n");


    fprintf(stderr, "Client specific options:\n");
    fprintf(stderr, "  -c, --client     <host>  run in client mode, connecting to <host>\n");
    fprintf(stderr, "  -r, --randomise          randomise data in every packet sent\n");
    fprintf(stderr, "  -P, --test-port  <port>  port number to test on (default %d)\n", DEFAULT_TEST_PORT);
    fprintf(stderr, "  -z, --write-size <bytes> length of buffer to write (default %d)\n",(int) DEFAULT_WRITE_SIZE );
    fprintf(stderr, "  -o, --sndbuf     <bytes> maximum size of the send (output) buffer\n");
    fprintf(stderr, "  -i, --rcvbuf     <bytes> maximum size of the receive (input) buffer\n");
    fprintf(stderr, "  -N, --nodelay            disable Nagle's Algorithm (set TCP_NODELAY)\n");
    fprintf(stderr, "  -M, --mss        <bytes> set TCP maximum segment size\n");
    fprintf(stderr, "  -S, --schedule   <seq>   test schedule (see below)\n");
    fprintf(stderr, "  -t, --time       <sec>   time in seconds to transmit (default 10s)\n");
    fprintf(stderr, "  -w, --disable-web10g     don't record Web10G results\n");
    fprintf(stderr, "\n");


    fprintf(stderr, "Miscellaneous:\n");
    fprintf(stderr, "  -h, --help               print this help\n");
    fprintf(stderr, "  -x, --debug              enable debug output\n");
    fprintf(stderr, "  -v, --version            print version information and exit\n");
    fprintf(stderr, "\n");


    fprintf(stderr, "Socket options such as rcvbuf, sndbuf, mss and nodelay "
            "will be set on both\n");
    fprintf(stderr, "the client and server. Web10G can be used to check these "
            "are set correctly.\n");
    fprintf(stderr, "\n");


    /* TODO make schedules like iperf? just do one way for a period */
    fprintf(stderr, "A schedule is a sequence of tests. Each test starts with single character\n");
    fprintf(stderr, "representing its type. Tests are separated by a single comma ','.\n");
    fprintf(stderr, "Valid types are:\n");
    fprintf(stderr, "  s<num_bytes> run a server -> client test, sending a fixed number of bytes\n");
    fprintf(stderr, "  S<num_bytes> run a client -> server test, sending a fixed number of bytes\n");
    fprintf(stderr, "  t<ms>        run a server -> client test, for the time given in milliseconds\n");
    fprintf(stderr, "  T<ms>        run a client -> server test, for the time given in milliseconds\n");
    fprintf(stderr, "  n            make a new test connection (close and reopen it)\n");
    fprintf(stderr, "  p<ms>        pause for the time given in milliseconds\n");
    fprintf(stderr, " e.g. -S \"t1000,T1000\"      Run two tests each for 1 second first S2C then C2S\n");
    fprintf(stderr, " e.g. -S \"s10000,n,S10000\"  Run two tests S2C then C2S each sending 10,000");
    fprintf(stderr, "                                  bytes with the connection reset in between\n");
}



/*
 * Print current AMP version and the throughput test protocol version.
 */
static void version(char *prog) {
    fprintf(stderr, "%s, amplet version %s, protocol version %d\n", prog,
            PACKAGE_STRING, AMP_THROUGHPUT_TEST_VERSION);
}



/*
 * Combined entry point for throughput tests that will run the appropriate
 * part of the test - server or client.
 */
amp_test_result_t* run_throughput(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    int option_index = 0;
    int server_flag_index = 0;

    Log(LOG_DEBUG, "Starting throughput test");

    /* XXX this option string needs to be up to date with server and client? */
    while ( (opt = getopt_long(argc, argv,
                    "?hvp:P:rsz:o:i:Nm:wS:c:d:4:6:I:t:Q:Z:",
                    long_options, &option_index)) != -1 ) {
        switch ( opt ) {
            case 's': server_flag_index = optind - 1; break;
            case 'v': version(argv[0]); exit(0);
            case '?':
            case 'h': usage(argv[0]); exit(0);
            default: break;
        };
    }

    /* reset optind so the next function can parse its own arguments */
    optind = 1;

    if ( server_flag_index ) {
        /* remove the -s option before calling the server function */
        memmove(argv + server_flag_index, argv + server_flag_index + 1,
                (argc - server_flag_index - 1) * sizeof(char *));
        run_throughput_server(argc-1, argv, NULL);
        return NULL;
    }

    return run_throughput_client(argc, argv, count, dests);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_THROUGHPUT;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("throughput");

    /* how many targets a single instance of this test can have  - Only 1 */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_throughput;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_throughput;

    /* function to call to start the throughput server */
    new_test->server_callback = run_throughput_server;

    /* don't give the throughput test a SIGINT warning */
    new_test->sigint = 0;

    return new_test;
}
