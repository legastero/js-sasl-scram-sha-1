(function(root, factory) {
  if (typeof exports === 'object') {
    // CommonJS
    factory(require('../lib/mechanism'));
  } else if (typeof define === 'function' && define.amd) {
    // AMD
    define(['sasl-scram-sha-1/lib/mechanism'], factory);
  }
}(this, function(Mechanism) {

  describe('Mechanism', function() {
    var mech = new Mechanism();
    
    it('should be named SCRAM-SHA-1', function() {
      expect(mech.name).to.equal('SCRAM-SHA-1');
    });
    
    it('should be client first', function() {
      expect(mech.clientFirst).to.equal(true);
    });
    
    it('should have chainable challenge function', function() {
      expect(mech.challenge('r=123456789,s=SECRETSALT,i=4096')).to.equal(mech);
    });
  });
  
  describe('response to challenge', function() {
    var mech = new Mechanism({
      genNonce: function() { return 'MsQUY9iw0T9fx2MUEz6LZPwGuhVvWAhc'; }
    });

    it('should create initial response', function () {
        var initial = mech.response({username: 'chris', password: 'secret'});
        expect(initial).to.equal('n,,n=chris,r=MsQUY9iw0T9fx2MUEz6LZPwGuhVvWAhc');
    });

    mech.challenge('r=MsQUY9iw0T9fx2MUEz6LZPwGuhVvWAhc7b276f42-009a-40e2-84ee-8d5c8b206b6a,s=OTFmZGE2ZGQtYjA0Yy00MTRiLTk1ZTktYTkyYWRlMmVkYTc5,i=4096');
    
    it('should encode credentials', function() {
      var enc = mech.response({username: 'chris', password: 'secret'});
      expect(enc).to.equal('c=biws,r=MsQUY9iw0T9fx2MUEz6LZPwGuhVvWAhc7b276f42-009a-40e2-84ee-8d5c8b206b6a,p=WKFCdDykcs73+CG653eG721vItw=');
    });
  });
  
  return { name: 'test.sasl-scram-sha-1.mechanism' };
  
}));
