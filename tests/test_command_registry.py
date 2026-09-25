"""Contract tests that custom commands stay registered and backed by scripts."""

from conf_utils import load_conf

EXPECTED_COMMANDS = {
    "gnip": "gnip.py",
    "gnquick": "gnquick.py",
    "gnippsychic": "gnippsychic.py",
    "gnquery": "gnquery.py",
    "gnrecall": "gnrecall.py",
    "gnstats": "gnstats.py",
    "gnmulti": "gnmulti.py",
    "gncontext": "gnip.py",
    "gnfilter": "gnfilter.py",
    "gnenrich": "gnenrich.py",
    "gncallback": "gncallback.py",
    "gncallbackfeed": "gncallbackfeed.py",
    "gnfeed": "gnfeed.py",
    "gnoverview": "greynoise_overview.py",
    "gniptimeline": "gniptimeline.py",
    "maintaincache": "cache_maintenance.py",
    "gncve": "gncve.py",
}


def test_commands_conf_maps_each_command_to_an_existing_script(app_dir):
    parser = load_conf(app_dir / "default" / "commands.conf")
    assert set(parser.sections()) == set(EXPECTED_COMMANDS)
    for name, filename in EXPECTED_COMMANDS.items():
        assert parser.get(name, "filename") == filename
        assert parser.get(name, "chunked") == "true"
        assert parser.get(name, "python.required") == "3.13"
        assert (app_dir / "bin" / filename).is_file()


def test_searchbnf_documents_public_commands(app_dir):
    text = (app_dir / "default" / "searchbnf.conf").read_text(encoding="utf-8")
    documented = {
        "gnip",
        "gnquick",
        "gnippsychic",
        "gnquery",
        "gnrecall",
        "gnstats",
        "gnmulti",
        "gnfilter",
        "gnenrich",
        "gncallback",
        "gncallbackfeed",
        "gnfeed",
        "gniptimeline",
        "gncve",
    }
    for command in documented:
        assert "[{}-command]".format(command) in text
