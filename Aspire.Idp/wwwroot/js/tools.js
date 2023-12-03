window.Tools = {

    // 解码html
    DecodeHtml(htmlString) {
        const element = document.createElement('div');
        element.innerHTML = htmlString;
        var str = element.textContent || element.innerText || '';
        element.remove();
        return str;
    },
    // 格式化日期时间
    FormatDateTime(date, format) {
        date = new Date(date);
        const padZero = (num) => (num < 10 ? '0' + num : num);

        const year = date.getFullYear();
        const month = padZero(date.getMonth() + 1);
        const day = padZero(date.getDate());
        const hour = padZero(date.getHours());
        const minute = padZero(date.getMinutes());
        const second = padZero(date.getSeconds());

        const formattedDate = format
            .replace('yyyy', year)
            .replace('MM', month)
            .replace('dd', day)
            .replace('HH', hour)
            .replace('mm', minute)
            .replace('ss', second);

        return formattedDate;
    }
}