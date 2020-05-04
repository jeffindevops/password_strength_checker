from optparse import OptionParser



def parse_options():
    """
    Handle command-line options with optparse.OptionParser.

    Return list of arguments, largely for use in `parse_arguments`.
    """

    # Initialize
    parser = OptionParser(usage="main options --file")

    parser.add_option(
        '-f', '--file',
        dest="file",
        default=None,
        help="Give /etc/shadow file"
    )


    # Finalize
    # Return three-tuple of parser + the output from parse_args (opt obj, args)
    opts, args = parser.parse_args()
    return parser, opts, args
