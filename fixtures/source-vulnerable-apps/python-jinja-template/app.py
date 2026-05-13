from fastapi import FastAPI, Request
from jinja2 import Template

app = FastAPI()


@app.post("/render")
async def render_template(request: Request) -> dict[str, str]:
    body = await request.json()
    template = Template(body["template"])
    return {"html": template.render(name=body.get("name", ""))}
