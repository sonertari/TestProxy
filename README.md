# TestProxy - Tool for end-to-end testing of proxy servers

Copyright (C) 2019, [Soner Tari](http://comixwall.org).  
https://github.com/sonertari/TestProxy

## Overview

TestProxy is a tool for end-to-end testing of proxy servers.

The main test harnesses file is composed of multiple test harnesses. Test 
harnesses are divided into multiple test sets, which are composed of tests 
defined in a test set file. Each test contains multiple states or steps.

TestProxy runs multithreaded. Test harnesses are run serially, starting from 
the first one. But TestProxy starts a manager thread for each test set in test 
harnesses. Manager thread runs the tests in its test set serially, but it 
starts a server and a client thread for each test in the test set. Manager 
thread communicates with those server and client threads over messaging 
channels, instructs them to send or receive payloads defined in test 
states, and expects execution results back.

Tests are defined in json files. Since protocol configuration, proxy and 
server addresses are test set specific, they are configured in json files for 
test sets. See the sample files under the `examples` folder.

TestProxy currently supports the TCP and SSL protocols.

## License

TestProxy is provided under the GPLv3 license.