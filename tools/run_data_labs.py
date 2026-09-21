#!/usr/bin/env python3
"""Run the eight reviewed, self-contained Phase 2/3 labs in disposable storage."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LABS = {
    'Phase2': ('api_file_ingestion', 'data_storage_file_formats', 'streaming_cdc', 'workflow_orchestration'),
    'Phase3': ('data_governance_lineage', 'data_recovery_replay', 'pipeline_observability', 'pipeline_testing_cicd'),
}


def main():
    with tempfile.TemporaryDirectory(prefix='guide-labs-') as folder:
        for phase, names in LABS.items():
            for name in names:
                source = ROOT / 'Data-Engineering' / phase / (name + '.md')
                blocks = re.findall(r'^```python\s*\n(.*?)^```', source.read_text(), re.M | re.S)
                if not blocks:
                    raise RuntimeError(f'Missing Python lab: {source}')
                script = Path(folder) / (name + '.py')
                script.write_text(blocks[0])
                print(f'Running {phase}/{name}', flush=True)
                subprocess.run([sys.executable, '-B', str(script)], cwd=folder, check=True, timeout=30)


if __name__ == '__main__':
    main()
