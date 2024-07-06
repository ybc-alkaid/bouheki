# Examples

#### Allow all signals

```yaml
signals:
  mode: monitor 
  type:
    deny:
      - SIGKILL
      - SIGTERM
      - SIGSTOP
    allow: []
```

