import cpp

from FunctionCall fcall
where
    fcall.getTarget().hasName("memcpy")
select fcall