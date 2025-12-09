**Anki query quoting (very important)**  
Always quote the **entire filter** (field/tag + `re:` + pattern):

| Goal | Example | Why |
|------|----------|-----|
| Fielded regex | `"Front:re:\\(word\\)"` | Quotes the full filter safely. |
| Tags regex | `"tag:re:^my_tag(::|$)"` | |
| OR multiple fields | `("Front:re:foo" OR "Back:re:foo")` | Parentheses ensure grouping. |

✅ Always quote the **entire** filter — `"Field:re:..."`  
❌ Don’t quote only the `re:` part — `Field:"re:..."`