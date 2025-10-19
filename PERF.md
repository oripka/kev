wright now performacne of initial showing the index page is very slow the statistics take time to load. when i click on Domain coverage

 or any of the others to filter it takes time or if i do nay of the other filters by year, kev list, cis , cvss, epss, plaintext search. my software, ransomware, internet exposure, named cve. focus on my software etc.

 we want to make this blazingly fast by doing the following. on data import / cached or otherwise you should run all the classifications as far as possible on everything and save that info strcuted in the database.

 so then we can mostly just do sql querries and no heavy lifting. any joining of the data or so should also be done on import. bascially never should you load the hwole kev list or cisa list or a merge of it into the app. any query should only be done against the database.. add the columns or tables necessary to make that happen.
 

 the end goal is that eveytifg loads and reactis blatzingly fast and we do all the heavy lifting on import

 also add another button that does the reclassifcaiton and so on of the cached data files so we can update ther databse when our algoruthsm for classifaiton or filters changed. 
 