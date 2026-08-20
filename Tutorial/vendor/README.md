# Decoder dependency overlay

`setup_ubuntu.sh` clones upstream LTESniffer commit
`a694803082017ac2b349e6b113940e8b9ba2fe5b`, overlays the checked-in files in
`ltesniffer-overlay/`, and builds a repository-local offline decoder.

The overlay contains the research changes required by this tutorial, including
offline file parameters, RA-RNTI boundary handling, diagnostic DCI/UL grant
records, SIB2/RRC configuration handling, hopping support, and UL decode audit
fields. LTESniffer retains its upstream license; the setup clone includes the
complete upstream `LICENSE` file.

Generated source and build trees are placed in `vendor/build/` and ignored by
Git.
