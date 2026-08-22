import json

from recon.output import save_json


def test_save_json(tmp_path):
    output_file = tmp_path / "result.json"

    data = {
        "target": "example.com",
        "ports": [
            {
                "port": 443,
                "service": "https",
            }
        ],
    }

    save_json(
        data=data,
        output_path=str(output_file),
    )

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        saved_data = json.load(file)

    assert saved_data == data