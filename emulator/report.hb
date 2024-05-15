<html>
<head>
    <title>portal {{#if result}}OK{{else}}ERR{{/if}}</title>
    <style type="text/css">
        table {
            width: 100%;
        }
        th, td {
            word-break: break-all;
            width: 50%;
            border: 1px solid black;
        }
        .pass {
            background-color: #00800030;
        }
        .fail {
            background-color: #ff000030;
        }
        display {
            display: block;
            height: 192px;
            width: 384px;
            margin: auto;
            background-size: cover;
            image-rendering: pixelated;
            opacity: 1;
        }
        display:active {
            opacity: 0.5;
        }
        pre {
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <table>
        <thead>
            <th>Actual</th>
            <th>Expected</th>
        </thead>
        <tbody>
        {{#each steps}}
            {{#if print_log_lines}}
                <tr><td>
<pre>
{{#each log_lines}}
{{this}}
{{/each}}
</pre>
                    </td><td></td>
                </tr>
            {{/if}}

                {{#if is_action}}
                    <tr>
                    <td><b>ACTION:</b>{{action}}</td>
                    <td></td>
                {{else}}
                    <tr class="{{#if pass}}pass{{else}}fail{{/if}}">
                    {{#if assertion.Display}}
                        <td>
                            {{#if fail.WrongDisplay}}
                                <display alt="click to copy!" style="background-image: url(data:image/png;base64,{{fail.WrongDisplay}})" data-img="{{fail.WrongDisplay}}"></display>
                            {{else}}
                                <display alt="click to copy!" style="background-image: url(data:image/png;base64,{{assertion.Display.content}})" data-img="{{assertion.Display.content}}"></display>
                            {{/if}}
                        </td>
                        <td><display alt="click to copy!" style="background-image: url(data:image/png;base64,{{assertion.Display.content}})" data-img="{{assertion.Display.content}}"></display></td>
                    {{else}}
                        <td>
                            {{#if fail.WrongReply}}
                                {{fail.WrongReply}}
                            {{else}}{{#if fail.NoReply}}
                                <i>No Reply</i>
                            {{else}}
                                {{assertion_json}}
                            {{/if}}{{/if}}
                        </td>
                        <td>{{assertion_json}}</td>
                    {{/if}}
                {{/if}}
            </tr>
        {{/each}}
        </tbody>
    </table>

    <script type="text/javascript">
    Array.from(document.getElementsByTagName("display")).forEach((e) => e.onclick = function(e) {
        navigator.clipboard.writeText(e.target.getAttribute("data-img"));
    })
    </script>
</body>
</html>