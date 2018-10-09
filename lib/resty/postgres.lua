-- Copyright (C) 2013 Azure Wang(azure1st@gmail.com)

local string = string
local table  = table
local bit    = bit
local ngx    = ngx
local tonumber = tonumber
local setmetatable = setmetatable
local error = error

module(...)

_VERSION = '0.2'

local STATE_CONNECTED = 1
local STATE_COMMAND_SENT = 2
local AUTH_REQ_OK = "\00\00\00\00"

local mt = { __index = _M }

--hex to binary function
local function hex2bin( hexstr )  
    local str = ''
    local len = #hexstr
    for i = 3, len - 1, 2 do    
        local doublebytestr = string.sub(hexstr, i, i+1);    
        local n = tonumber(doublebytestr, 16);    
        if 0 == n then 
            str = str .. '\00'  
        else
            str = str .. string.format("%c", n)  
        end
    end   
    return str  
end 

local converters = {}
-- Bytea data need unescape to real binary data
converters[17] = hex2bin
-- INT8OID
converters[20] = nil   --int64不转换为number，lua5.1支持不好
-- INT2OID
converters[21] = tonumber
-- INT2VECTOROID
converters[22] = tonumber
-- INT4OID
converters[23] = tonumber
-- FLOAT4OID
converters[700] = tonumber
-- FLOAT8OID
converters[701] = tonumber
-- NUMERICOID
converters[1700] = tonumber

function new(self)
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    -- only new connection have env info
    return setmetatable({ sock = sock, env = {}}, mt)
end

function set_timeout(self, timeout)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    return sock:settimeout(timeout)
end

local function _get_byte4(data, i)
    local a, b, c, d = string.byte(data, i, i+3)
    return bit.bor(bit.lshift(a, 24), bit.lshift(b, 16), bit.lshift(c, 8), d), i+4
end

local function _get_byte2(data, i)
    local a, b = string.byte(data, i, i+1)
    return bit.bor(bit.lshift(a, 8), b), i+2
end

local function _get_data_n(data, len, i)
    local d = string.sub(data, i, i+len-1)
    return d, i+len
end

local function _set_byte2(n)
    return string.char(bit.band(bit.rshift(n, 8), 0xff), bit.band(n, 0xff))
end

local function _set_byte4(n)
    return string.char(bit.band(bit.rshift(n, 24), 0xff), bit.band(bit.rshift(n, 16), 0xff),
                       bit.band(bit.rshift(n, 8), 0xff), bit.band(n, 0xff))
end

local function _from_cstring(data, i)
    local last = string.find(data, "\0", i, true)
    if not last then
        return nil, nil
    end
    return string.sub(data, i, last - 1), last + 1
end

local function _to_cstring(data)
    return {data, "\0"}
end

function _send_packet(self, data, len, typ)
    local sock = self.sock
    local packet
    if typ then
        packet = {
            typ,
            _set_byte4(len),
            data
        }
    else
        packet = {
            _set_byte4(len),
            data
        }
    end
    return sock:send(packet)
end

function _parse_error_packet(packet)
    local pos = 1
    local flg, value, msg
    msg = {}
    while true do
       flg = string.sub(packet, pos, pos)
       if not flg then
           return nil, "parse error packet fail"
       end
       pos = pos + 1
       if flg == '\0' then
          break
       end

       -- all flg S/V/C/M/D/H/P/p/q/W/s/t/c/d/n/F/L/R
       -- refer https://www.postgresql.org/docs/10/static/protocol-error-fields.html
       -- S/V : Severity
       -- C : Code: the SQLSTATE code for the error 
       -- M : Message: the primary human-readable error message
       -- D : Detail
       -- H : Hint: an optional suggestion what to do about the problem
       -- P : Position
       -- p : Internal position
       -- q : Internal query
       -- W : Where: an indication of the context in which the error occurred
       -- s : Schema name
       -- t : Table name
       -- c : Column name
       -- d : Data type name
       -- n : Constraint name
       -- debug flag  F,L,R : File,Line,Routine

       value, pos = _from_cstring(packet, pos)
       if not value then
           return nil, "parse error packet fail"
       end
       msg[flg] = value
   end
   return msg
end

function _recv_packet(self)
    -- receive type
    local sock = self.sock
    local typ, err = sock:receive(1)
    if not typ then
        return nil, nil, "failed to receive packet type: " .. err
    end
    -- receive length
    local data, err = sock:receive(4)
    if not data then
        return nil, nil , "failed to read packet length: " .. err
    end
    local len = _get_byte4(data, 1)
    if len <= 4 then
        return nil, typ, "empty packet"
    end
    -- receive data
    data, err = sock:receive(len - 4)
    if not data then
        return nil, nil, "failed to read packet content: " .. err
    end
    --ngx.log(ngx.INFO, typ..'/'..len..'/'..data)
    return data, typ
end

function _compute_token(self, user, password, salt)
    local token1 = ngx.md5(password .. user)
    local token2 = ngx.md5(token1 .. salt)
    return "md5" .. token2
end

function connect(self, opts)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    
    local ok, err

    self.compact = opts.compact

    local host = opts.host
    local database = opts.database or ""
    local user = opts.user or ""
    local host = opts.host
    local pool = opts.pool
    local password = opts.password

    if host then
        local port = opts.port or 5432
        if not pool then
            pool = table.concat({user, database, host, port}, ":")
        end
        ok, err = sock:connect(host, port, { pool = pool })
    else
        local path = opts.path
        if not path then
            return nil, 'neither "host" nor "path" options are specified'
        end

        if not pool then
            pool = table.concat({user, database, path}, ":")
        end

        ok, err = sock:connect("unix:" .. path, { pool = pool })
    end
    if not ok then
        return nil, 'failed to connect: ' .. err
    end

    local reused = sock:getreusedtimes()
    -- use pool connection
    if reused and reused > 0 then
        self.state = STATE_CONNECTED
        return 1
    end
    -- new connection
    -- send first packet
    local req, req_len
    req = {}
    -- PG_PROTOCOL  3.0
    table.insert(req, {"\00\03","\00\00"})
    table.insert(req, _to_cstring("user"))
    table.insert(req, _to_cstring(user))
    table.insert(req, _to_cstring("database"))
    table.insert(req, _to_cstring(database))
    table.insert(req, "\00")
    -- packet_len + PG_PROTOCOL + user + database + end
    -- req_len = 4 + 4 + string.len(user) + 6 + string.len(database) + 10 + 1
    req_len = string.len(user) + string.len(database) + 25
    local bytes, err = _send_packet(self, req, req_len)
    if not bytes then
        return nil, "failed to send client authentication packet1: " .. err
    end    
    -- receive salt packet (len + data) no type
    local packet, typ
    packet, typ, err = _recv_packet(self)
    if not packet then
        return nil, "handshake error:" .. err
    end
    if typ ~= 'R' then
        return nil, "handshake error, got packet type:" .. typ
    end
    --Authentication Type 验证类型
    --2 声明需要 Kerberos V5 认证
    --3 声明需要一个明文的口令
    --4 声明需要一个 crypt() 加密的口令。
    --5 声明需要一个 MD5 加密的口令
    local auth_type = _get_byte4(string.sub(packet, 1, 4),1)
    local salt = string.sub(packet, 5, 8)
    -- send passsowrd
    if auth_type == 3 then
      req = {_to_cstring(password)}
      req_len = #password + 1 + 4
    elseif auth_type == 5 then
      req = {_to_cstring(_compute_token(self, user, password, salt))}
      req_len = 40  -- len(req) + len(int) = 36 + 4
    end
    --ngx.log(ngx.INFO, string.format('auth_type:%s, data_len:%s', auth_type, string.len(req[1][1])))
    local bytes, err = _send_packet(self, req, req_len, 'p')
    if not bytes then
        return nil, "failed to send client authentication packet2: " .. err
    end
    -- receive response
    packet, typ, err = _recv_packet(self)
    if typ ~= 'R' then
        --[[if typ == 'E' then
            return nil,packet
        end--]]
        return nil, "auth return type not support"
    end
    if packet ~= AUTH_REQ_OK then
        return nil, "authentication failed"
    end
    while true do
        packet, typ, err = _recv_packet(self)
        if not packet then
            return nil, "read packet error:" .. err
        end
        -- env
        if typ == 'S' then
            local pos = 1
            local k, pos = _from_cstring(packet, pos)
            local v, pos = _from_cstring(packet, pos)
            self.env[k] = v
        end
        -- secret key
        if typ == 'K' then
            local pid = _get_byte4(packet, 1)
            local secret_key = string.sub(packet, 5, 8)
            self.env.secret_key = secret_key
            self.env.pid = pid
        end
        -- error
        if typ == 'E' then
            local msg = _parse_error_packet(packet)
            return nil, "Get error packet:" .. msg.M, msg.C
        end
        -- ready for new query
        if typ == 'Z' then
            self.state = STATE_CONNECTED
            return 1
        end
    end
end

function set_keepalive(self, ...)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    if self.state ~= STATE_CONNECTED then
        return nil, "cannot be reused in the current connection state: "
                    .. (self.state or "nil")
    end
    self.state = nil
    return sock:setkeepalive(...)
end

function get_reused_times(self)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    return sock:getreusedtimes()
end

function close(self)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    self.state = nil
    return sock:close()
end

function send_query(self, query)
    if self.state ~= STATE_CONNECTED then
        return nil, "cannot send query in the current context: "
                    .. (self.state or "nil")
    end
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    local typ = 'Q'
    local data = _to_cstring(query)
    -- packet_len + cstring end(\0) = 5
    local len = string.len(query) + 5
    local bytes, err = _send_packet(self, data, len, typ)
    self.state = STATE_COMMAND_SENT
    return bytes, err
end

function read_result(self)
    if self.state ~= STATE_COMMAND_SENT then
        return nil, "cannot read result in the current context: " .. self.state
    end
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    -- read data
    local res = {}
    local fields = {}
    local field_ok = false
    local packet, typ, err, errcode
    while true do
        packet, typ, err = _recv_packet(self)
        if not packet then
            return nil, "read result packet error:" .. err
        end
        -- packet of fields
        if typ == 'T' then
            local field_num, pos = _get_byte2(packet, 1)
            for i=1, field_num do
                local field = {}
                field.name, pos = _from_cstring(packet, pos)
                field.table_id, pos = _get_byte4(packet, pos)
                field.field_id, pos = _get_byte2(packet, pos)
                field.type_id, pos  = _get_byte4(packet, pos)
                field.type_len, pos = _get_byte2(packet, pos)
                -- pass atttypmod, format
                pos = pos + 6
                table.insert(fields, field)
            end
            field_ok = true
        end
        -- packet of data row
        if typ == 'D' then
            if not field_ok then
                return nil, "not receive fields packet"
            end
            local row = {}
            local row_num, pos = _get_byte2(packet, 1)
            -- get row
            for i=1, row_num do
                local data, len
                len, pos = _get_byte4(packet, pos)
                if len == -1 then
                    data = ngx.null
                else
                    data, pos = _get_data_n(packet, len, pos)
                end
                local field = fields[i]
                --ngx.log(ngx.INFO, string.format("%s,%s,%s,%s,%s,%s",field.name,field.table_id,field.field_id,field.type_id,field.type_len,len))
                --ngx.log(ngx.INFO, data)
                local conv = converters[field.type_id]
                if conv and data ~= ngx.null then
                    data = conv(data)
                end
                if self.compact then
                    table.insert(row, data)
                else
                    local name = field.name
                    row[name] = data
                end
            end 
            table.insert(res, row)
        end
        if typ == 'E' then
            -- error packet
            local msg = _parse_error_packet(packet)
            err = msg.M
            errcode = msg.C
            res = nil
            --do not break,there have something in buffer need to read,otherwise will cause the func set_keepalive fail
            --break
        end
        if typ == 'C' then
            -- read complete
            local sql_type = _from_cstring(packet, 1)
            self.env.sql_type = sql_type
            err = nil
        end
        if typ == 'Z' then
            self.state = STATE_CONNECTED
            break
        end
    end   
    return res, err, errcode
end

function query(self, query)
    local bytes, err = send_query(self, query)
    if not bytes then
        return nil, "failed to send query: " .. err
    end

    return read_result(self)
end

function escape_string(str)
    local new = string.gsub(str, "['\\]", "%0%0")
    return new
end

local class_mt = {
    -- to prevent use of casual module global variables
    __newindex = function (table, key, val)
        error('attempt to write to undeclared variable "' .. key .. '"')
    end
}

setmetatable(_M, class_mt)
