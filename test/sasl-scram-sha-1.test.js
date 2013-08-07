(function(root, factory) {
  if (typeof exports === 'object') {
    // CommonJS
    factory(require('../main'));
  } else if (typeof define === 'function' && define.amd) {
    // AMD
    define(['sasl-scram-sha-1'], factory);
  }
}(this, function(saslscramsha1) {

  describe('sasl-scram-sha-1', function() {
    
    it('should export Mechanism', function() {
      expect(saslscramsha1.Mechanism).to.be.a('function');
    });
    
    it('should export Mechanism via module', function() {
      expect(saslscramsha1).to.equal(saslscramsha1.Mechanism);
    });
    
  });
  
  return { name: 'test.sasl-scram-sha-1' };
  
}));
