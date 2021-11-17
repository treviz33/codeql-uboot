import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(MacroInvocation minv | minv.getExpr() = this and minv.getMacroName().regexpMatch("ntoh.+"))
  }
}

from NetworkByteSwap n
select n, "Network byte swap"