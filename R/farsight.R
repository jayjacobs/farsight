#' Load the API key for DNSDB API
#' 
#' This reads in a an "analysis.cfg" Python configparser file with API keys and 
#' extracts the key for dnsdp_api into an environment variable for use in the
#' API.
#' 
#' The file could have one line that loos like this: 
#' dnsdb_api=0dc45ef13ebbe51188e7a7778c019e7c4fe41db9c43ea06866297c88b42bad35
#'
#' @param configFilePath path to the configuration file
#' @export
#' @examples
#' \dontrun{
#' readConfig("~/.analysis.cfg")
#' }
#'
readConfig <- function(configFilePath) {
  
  config <- Parse.INI(configFilePath)
  
  if ("dnsdb_api" %in% names(config$ScavengeIP)) Sys.setenv(FARSIGHT_PAT=config$ScavengeIP$dnsdb_api)
  
}

#' Internal function to load an INI file
#' 
#' via http://r.789695.n4.nabble.com/Read-Windows-like-INI-files-into-R-data-structure-td827353.html
Parse.INI <- function(INI.filename) {
  
  connection <- file(INI.filename)
  Lines  <- readLines(connection)
  close(connection)
  
  Lines <- chartr("[]", "==", Lines)  # change section headers
  
  connection <- textConnection(Lines)
  d <- read.table(connection, as.is = TRUE, sep = "=", fill = TRUE)
  close(connection)
  
  L <- d$V1 == ""                    # location of section breaks
  d <- subset(transform(d, V3 = V2[which(L)[cumsum(L)]])[1:3], V1 != "")
  
  ToParse  <- paste("INI.list$", d$V3, "$",  d$V1, " <- \"",
                    as.character(d$V2), "\"", sep="") # if numeric values!
  
  INI.list <- list()
  eval(parse(text=ToParse))
  
  return(INI.list)
  
}

# Retrieve the farsight API key from env var or key it in
#
# @param force require keyboard entry
#
farsight_pat <- function(val=NULL, force=FALSE) {
  if (!is.null(val)) {
    return(val)
  }
  env <- Sys.getenv('FARSIGHT_PAT')
  if (!identical(env, "") && !force) return(env)
  
  if (!interactive()) {
    stop("Please set env var FARSIGHT_PAT to your farsight personal access token",
         call. = FALSE)
  }
  
  message("Couldn't find env var FARSIGHT_PAT See ?farsight_pat for more details.")
  message("Please enter your PAT and press enter:")
  pat <- readline(": ")
  
  if (identical(pat, "")) {
    stop("VirusTotal personal access token entry failed", call. = FALSE)
  }
  
  message("Updating FARSIGHT_PAT env var to PAT")
  Sys.setenv(FARSIGHT_PAT = pat)
  
  pat
}

#' Perform a "forward" lookup based on the owner name of an RRset. 
#' 
#' Look up the RRset data for a given name, can optionally filter based on the 
#' RRType or the bailiwick scope.
#' 
#' This will attempt to convert the date/time fields to POSIXct objects and if those are 
#' found, it will attempt to calculate the difference (in days) between the last seen and 
#' first seen record.  Keep an eye out because some of the return values in the columns may 
#' be lists and not easy vectors, specifically the \code{rdata} column.
#' 
#' @seealso \link{https://api.dnsdb.info/}
#' 
#' @param name the domain being searched, may contain wildcard "*" symbol
#' @param rrtype optional filter of DNS RRtype field
#' @param bailiwick optional filter for bailiwick
#' @param limit the maximum number of values to return
#' @param pat the DNSDB API key (if supplied manually) to use, otherwise this 
#' will try to pull what was loaded from \link{readConfig}, and if that doesn't work 
#' and the session is interactive, it will prompt for the API key.
#' @export
#' @import httr, jsonlite
#' 
rrset <- function(name, rrtype=NULL, bailiwick=NULL, limit=NULL, pat=NULL) {
  pat <- farsight_pat(pat)
  query <- paste("https://api.dnsdb.info/lookup/rrset/name", name, sep="/")
  if (!is.null(rrtype)) {
    query <- paste(query, rrtype, sep="/")
    if (!is.null(bailiwick)) {
      query <- paste(query, bailiwick, sep="/")
    }
  }
  if (!is.null(limit) && is.integer(limit)) {
    query <- paste(query, limit, sep="?limit=")
  }
  req <- GET(query,
             add_headers(`Content-type`="application/json",
                         `Accept`="application/json",
                         `X-Api-Key`=pat))
  rez <- getresult(req)
  if (is.numeric(rez)) {
    warning(paste0("rrset: ", rez, " status returned for ", name, "."))
    return()
  }
  rez
}

#' Internal function: given a request for data, returns a data frame of the results
getresult <- function(req) {
  if(req$status_code >= 400) {
    return(req$status_code)
  }
  tmp.lines <- readLines(textConnection(content(req, type="text")))
  tmp.df <- fromJSON(sprintf("[%s]", paste(tmp.lines[tmp.lines != ""], sep="", collapse=",")))
  tmp.df$time_first <- as.POSIXct(tmp.df$time_first, origin="1970-01-01")
  tmp.df$time_last <- as.POSIXct(tmp.df$time_last, origin="1970-01-01")
  if ("zone_time_first" %in% colnames(tmp.df)) tmp.df$zone_time_first <- as.POSIXct(tmp.df$zone_time_first, origin="1970-01-01")
  if ("zone_time_last" %in% colnames(tmp.df)) tmp.df$zone_time_last <- as.POSIXct(tmp.df$zone_time_last, origin="1970-01-01")
  tmp.df <- with(tmp.df, tmp.df[rev(order(time_last)),])
  rownames(tmp.df) <- NULL
  tmp.df$diffdays <- as.numeric(difftime(tmp.df$time_last, tmp.df$time_first, units="days"))
  tmp.df$diffdays[is.na(tmp.df$time_first)] <- NA
  if ("zone_time_first" %in% colnames(tmp.df)) {
    tmp.df$zone_diffdays <- as.numeric(difftime(tmp.df$zone_time_last, tmp.df$zone_time_first, units="days"))
    tmp.df$zone_diffdays[is.na(tmp.df$zone_time_first)] <- NA
  }
  tmp.df
}