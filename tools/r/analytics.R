args <- commandArgs(trailingOnly=TRUE)
input <- ifelse(length(args) >= 1, args[[1]], "data/findings/submissions.jsonl")
cat(sprintf("{\"module\":\"r_analytics\",\"input\":\"%s\",\"note\":\"Use R for deeper payout and acceptance modeling.\"}\n", input))
