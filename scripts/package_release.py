"""Build the source release without local data, credentials or environments."""
from pathlib import Path
import hashlib
import zipfile
import json
import sys
import os
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root))
from cbb.schema import WireEvent
from cbb.config import Settings
from cbb.api import create_app
docs=root/'docs'
(docs/'ingest.schema.json').write_text(json.dumps(WireEvent.model_json_schema(),indent=2),encoding='utf-8')
app=create_app(Settings(data=root/'work/schema-data',workers=False))
(docs/'openapi.json').write_text(json.dumps(app.openapi(),indent=2),encoding='utf-8')
app.state.service.db.engine.dispose()
out=root/'release';out.mkdir(exist_ok=True)
target=out/'Cyber-Black-Box-Complete-Project.zip'
allowed={'cbb','web','tests','deploy','scripts','rules','docs','.github','output','source','test-kit'}
rootfiles={'README.md','pyproject.toml','requirements.lock','Dockerfile','.dockerignore','.gitignore','compose.virtual.yml','compose.cloud.yml','Start-Cyber-Black-Box.cmd'}
excluded={'node_modules','__pycache__','.pytest_cache','live-lab'}
count=0
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
    selected=[root/name for name in sorted(rootfiles) if (root/name).is_file()]
    for top in sorted(allowed):
        for directory,dirs,files in os.walk(root/top,followlinks=False):
            dirs[:]=sorted(d for d in dirs if d not in excluded and not (Path(directory)/d).is_symlink())
            selected.extend(Path(directory)/name for name in sorted(files))
    for path in selected:
        if path.is_symlink() or path.suffix in ('.pyc','.tsbuildinfo'):continue
        rel=path.relative_to(root)
        z.write(path,'Cyber-Black-Box/'+rel.as_posix());count+=1
digest=hashlib.sha256(target.read_bytes()).hexdigest()
(out/'SHA256SUMS.txt').write_text(digest+'  '+target.name+'\n')
print(json.dumps({'file':str(target),'files':count,'bytes':target.stat().st_size,'sha256':digest},indent=2))
