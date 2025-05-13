module example.com/includee

go 1.24.0

replace example.com/greetings => ../test_package/

require example.com/greetings v0.0.0-00010101000000-000000000000
