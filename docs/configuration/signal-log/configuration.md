# Current configuration options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable restrictions or not. Default is `true`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, events are only logged. If `block` is specified, network access is blocked. |
# Current Configuration Options

| Config | Type | Description |
|:------:|:----:|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable restrictions or not. Default is `true`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, events are only logged. If `block` is specified, network access is blocked. |
| `type` | Enum | Supported signal types. See the table below for names, signal numbers, and descriptions. |

# Supported Signal Types

| Signal Name | Signal Number | Description |
|:-----------:|:-------------:|:-----------:|
| `SIGHUP`    | 1             | Hangup detected on controlling terminal or death of controlling process. |
| `SIGINT`    | 2             | Interrupt from keyboard (Ctrl+C). |
| `SIGQUIT`   | 3             | Quit from keyboard. |
| `SIGILL`    | 4             | Illegal instruction. |
| `SIGABRT`   | 6             | Abort signal from `abort(3)`. |
| `SIGFPE`    | 8             | Floating-point exception. |
| `SIGKILL`   | 9             | Kill signal (cannot be caught or ignored). |
| `SIGSEGV`   | 11            | Invalid memory reference. |
| `SIGPIPE`   | 13            | Broken pipe: write to pipe with no readers. |
| `SIGALRM`   | 14            | Timer signal from `alarm(2)`. |
| `SIGTERM`   | 15            | Termination signal. |
