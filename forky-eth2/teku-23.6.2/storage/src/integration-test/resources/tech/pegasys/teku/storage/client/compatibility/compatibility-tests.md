# Compatibility Test Data

This directory contains test data in each format teku supports to allow compatibility tests to check
it can still be loaded with the latest code.

When changes are made to the test data, these files can be regenerated by running
`DatabaseCompatibilityTest.recreateDatabaseFiles`. Be sure to run it on a machine that supports 
both LevelDB and RocksDB.

The data files should *not* be regenerated if the test data hasn't changed - if that's required then 
backwards compatibility has been broken and the code needs to be fixed.