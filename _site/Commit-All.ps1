$old_pwd = $pwd
Set-Location ~\www\OmniSl4sh.github.io
git add .; git status;pause; git commit -m '+1'; git push
Set-Location $old_pwd