import cpp

from MacroInvocation minv
where
    minv.getMacroName().regexpMatch("ntoh.+")
select minv