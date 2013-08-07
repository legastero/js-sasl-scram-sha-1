# SASL : SCRAM-SHA-1

This module is a JavaScript implementation of the SCRAM-SHA-1 SASL mechanism,
which plugs into the [SASL](https://github.com/jaredhanson/js-sasl) framework.

## Install

##### npm

    $ npm install sasl-scram-sha-1

##### volo

    $ volo add legastero/js-sasl-scram-sha-1 sasl-scram-sha-1

For more information on using volo to manage JavaScript modules, visit [http://volojs.org/](http://volojs.org/).

## Usage

Register the SCRAM-SHA-1 mechanism.

```javascript
factory.use(require('sasl-scram-sha-1'));
```

Send an authentication response with necessary credentials.

```
var mech = factory.create(['SCRAM-SHA-1']);
var initial = mech.response({username: 'chris', password: 'secret'});

var secondResp = mech.challenge('r="XCV234BAL90",s="XMXC234DFS",i=4096')
                     .response({username: 'chris', password: 'secret'});
```

## TODO

Currently missing features:

- Mutual authentication of the server based on the success message.

## Compatibility

##### Browser

This module is [AMD](https://github.com/amdjs/amdjs-api)-compliant, and can be
loaded by module loaders such as [RequireJS](http://requirejs.org/).

##### Node

This module is compatible with [Node](http://nodejs.org/).

## Tests

##### Browser

To run tests in a browser, execute the Make target for the desired browser:

    $ make test-chrome
    $ make test-firefox
    $ make test-safari

##### PhantomJS

To run headless tests from a terminal using [PhantomJS](http://phantomjs.org/):

    $ make test-phantomjs

##### Node

To run tests in Node:

    $ make test-node
    
##### Status

[![Travis CI](https://secure.travis-ci.org/legastero/js-sasl-scram-sha-1.png)](http://travis-ci.org/legastero/js-sasl-scram-sha-1)

## Credits

  - [Lance Stout](http://github.com/legastero)
  - [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2013 Lance Stout <[http://github.com/legasteros/](http://github.com/legastero/)>
Copyright (c) 2012 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
