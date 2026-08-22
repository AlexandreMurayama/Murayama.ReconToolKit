import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def save_json(data: dict, output_path: str) -> None:
    path = Path(output_path)

    try:
        if path.parent != Path("."):
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        with path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False,
            )

    except OSError as error:
        logger.debug(
            "Unable to save JSON to %s: %s",
            output_path,
            error,
        )

        raise ValueError(
            f"Unable to save output file: {output_path}"
        ) from error