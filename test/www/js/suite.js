define(['require',
        'mocha',
        'chai',
        'mocha-cloud'],
function(require, mocha, chai, cloud) {
  mocha.setup('bdd');
  expect = chai.expect
  
  require(['test/sasl-scram-sha-1.test',
           'test/sasl-scram-sha-1.mechanism.test'],
  function() {
    if (window.mochaPhantomJS) { mochaPhantomJS.run(); }
    else { cloud(mocha.run()); }
  });
});
