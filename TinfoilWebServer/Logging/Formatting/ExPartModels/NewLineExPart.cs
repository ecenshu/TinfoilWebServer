﻿using System;
using TinfoilWebServer.Logging.Formatting.BasePartModels;

namespace TinfoilWebServer.Logging.Formatting.ExPartModels;

public class NewLineExPart : NewLineBasePart, IExPart
{
    public string GetText(Exception ex)
    {
        return NewLine;
    }
}