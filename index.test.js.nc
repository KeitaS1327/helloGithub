'use strict';
var gp = require('../');
var expect = require('expect');
var isWin32 = require('os').platform() === 'win32';
describe('glob-parent', function () {
  it('should strip glob magic to return parent path', function (done) {
    expect(gp('.')).toEqual('.');
    expect(gp('.*')).toEqual('.');
    expect(gp('/.*')).toEqual('/');
    expect(gp('/.*/')).toEqual('/');
    expect(gp('a/.*/b')).toEqual('a');
    expect(gp('a*/.*/b')).toEqual('.');
    expect(gp('*/a/b/c')).toEqual('.');
    expect(gp('*')).toEqual('.');
    expect(gp('*/')).toEqual('.');
    expect(gp('**/')).toEqual('.');
    expect(gp('**')).toEqual('.');
    expect(gp('**/')).toEqual('.');
    expect(gp('***/')).toEqual('.');
    expect(gp('*.js')).toEqual('.');
    expect(gp('{a,b}')).toEqual('.');
    expect(gp('/{a,b}')).toEqual('/');
    expect(gp('/{a,b}/')).toEqual('/');
    expect(gp('(a|b)')).toEqual('.');
    expect(gp('/(a|b)')).toEqual('/');
    expect(gp('./(a|b)')).toEqual('.');
    expect(gp('a/(b c)')).toEqual('a'); 
    expect(gp('a/(b c)/')).toEqual('a/(b c)'); 
    expect(gp('a/(b c)/d')).toEqual('a/(b c)'); 
    expect(gp('path/tofoo')).toEqual('path');
    expect(gp('path/@/foo')).toEqual('path/@');
    expect(gp('path/!/foo/')).toEqual('path/!/foo');
    expect(gp('path/?/foo/')).toEqual('path/?/foo');
    expect(gp('path/+/foo/')).toEqual('path/+/foo');
    expect(gp('path*')).toEqual('path');
    expect(gp('pathsubdir/foo.*')).toEqual('path');
    expect(gp('path/subdirfoo.js')).toEqual('path/subdir');
    expect(gp('path/!subdir/foo.js')).toEqual('path/!subdir');
    expect(gp('path/{foo,bar}/')).toEqual('path');
    done();
  });
  it('should respect escaped characters', function (done) {
    expect(gp('path/\\*\\*/subdir/foo.*')).toEqual('pathsubdir');
    expect(gp('path/\\[\\*\\]/subdir/foo.*')).toEqual('path/[*]/subdir');
    expect(gp('path/\\*(a|b)/subdir/foo.*')).toEqual('path');
    expect(gp('path/\\*/(a|b)/subdir/foo.*')).toEqual('path
    expect(gp('path/{,/,bar/baz,qux}/')).toEqual('path');
    expect(gp('path/\\{,/,bar/baz,qux}/')).toEqual('path/{,/,bar/baz,qux}');
    expect(gp('path/\\{,/,bar/baz,qux\\}/')).toEqual('path/{,/,bar/baz,qux}');
    expect(gp('/{,/,bar/baz,qux}/')).toEqual('/');
    expect(gp('/\\{,/,bar/baz,qux}/')).toEqual('/{,/,bar/baz,qux}');
    expect(gp('{,/,bar/baz,qux}')).toEqual('.');
    expect(gp('\\{,/,bar/baz,qux\\}')).toEqual('{,/,bar/baz,qux}');
    expect(gp('\\{,/,bar/baz,qux}/')).toEqual('{,/,bar/baz,qux}');
    expect(gp('path/foo[a\\/]/')).toEqual('path');
    expect(gp('path/foo\\[a\\/]/')).toEqual('path/foo[a\\/]');
    expect(gp('foo[a\\/]')).toEqual('.');
    expect(gp('foo\\[a\\/]')).toEqual('foo[a\\/]');
    expect(gp('path/(foo/bar|baz)')).toEqual('path');
    expect(gp('path/(foo/bar|baz)/')).toEqual('path');
    expect(gp('path/\\(foo/bar|baz)/')).toEqual('path/(foo/bar|baz)');
    done();
  });
  it('should handle nested braces', function (done) {
    expect(gp('path/{../,./,{bar,/baz\\},qux\\}/')).toEqual('path');
    expect(gp('path/{../,./,\\{bar,/baz},qux}/')).toEqual('path');
    expect(gp('path/\\{../,./,\\{bar,/baz\\},qux\\}/')).toEqual(
      'path/{../,./,{bar,/baz},qux}'
    );
    expect(gp('{../,./,{bar,/baz\\},qux\\}/')).toEqual('.');
    expect(gp('{../,./,{bar,/baz\\},qux\\}')).toEqual('.');
    expect(gp('path/{,/,bar/{baz,qux\\}}/')).toEqual('path');
    expect(gp('path/{,/,bar/{baz,qux}\\}/')).toEqual('path');
    done();
  });
  it('should return parent dirname from non-glob paths', function (done) {
    expect(gp('path')).toEqual('.');
    expect(gp('path/foo')).toEqual('path');
    expect(gp('path/foo/')).toEqual('path/foo');
    expect(gp('path/foo/bar.js')).toEqual('path/foo');
    done();
  });
  it('should respect disabled auto flip backslashes', function (done) {
    expect(gp('foo-\\(bar\\).md', { flipBackslashes: false })).toEqual('.');
    done();
  });
});
describe('glob2base test patterns', function () {
  it('should get a base name', function (done) {
    expect(gp('jstest{test,another}{images,components}dooga/{eooga,fooga}')).toEqual('ooga');
    done();
  });
  it('should not be susceptible to SNYK-JS-GLOBPARENT-1016905', function (done) {
    gp('{' + '/'.repeat(5000));
    done();
  });
  it("should finish in reasonable time for '{' + '/'.repeat(n) [CVE-2021-35065]", function (done) {
    this.timeout(1000);
    gp('{' + '/'.repeat(500000));
    done();
  });
  it("should finish in reasonable time for '{'.repeat(n)", function (done) {
    this.timeout(1000);
    gp('{'.repeat(500000));
    done();
  });
  it("should finish in reasonable time for '('.repeat(n)", function (done) {
    this.timeout(1000);
    gp('('.repeat(500000));
    done();
  });
  it("should finish in reasonable time for '/('.repeat(n) + ')'", function (done) {
    this.timeout(1000);
    gp('/('.repeat(500000) + ')');
    done();
  });
});
if (isWin32) {
  describe('technically invalid windows globs', function () {
    it('should manage simple globs with backslash path separator', function (done) {
      expect(gp('C:\\path\\*.js')).toEqual('C:/path');
      done();
    });
  });
}
