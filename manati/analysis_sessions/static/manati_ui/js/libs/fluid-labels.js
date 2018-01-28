(function ($) {
  var DEFAULT_OPTIONS = {
    inputOffsetTop: 5,
    animationDuration: 200,
    focusClass: null
  };

  function FluidLabel (container, options) {
    var self = this;
    this.options = $.extend({}, DEFAULT_OPTIONS, options || {});
    this.container = $(container);
    this.element = this.container.find('input,textarea');
    this.label = this.container.find('label');

    if (this.label.length === 0) {
      if (this.element.attr('placeholder')) {
        this.label = $('<label>').text(this.element.attr('placeholder'));
        this.label.insertAfter(this.element);
      } else {
        // nothing to do here
        return;
      }
    }

    if (this.element.val().trim().length > 0) {
      this.showLabel(false);
    } else {
      this.hideLabel(false);
    }
    this.label.css({left: 11,//this.element.position().left,
        top: this.options.labelTopOffset});

    this.element.on('keyup', function () {
      self.onValueChanged();
    });
    this.element.on('change', function () {
      self.onValueChanged();
    });
    if (this.options.focusClass) {
      this.element.on('focus', function () {
        self.onFocused();
      });
      this.element.on('blur', function () {
        self.blurred();
      });
    }
  }

  FluidLabel.prototype.onValueChanged = function () {
    var value = this.element.val();
    if (value.length > 0 && !this.active) {
      this.showLabel();
    } else if (value.length === 0 && this.active) {
      this.hideLabel();
    }
  };

  FluidLabel.prototype.showLabel = function (animation) {
    if (animation !== false) {
      this.label.fadeIn(this.options.animationDuration);
      this.element.animate({top: this.options.inputOffsetTop}, this.options.animationDuration);
    } else {
      this.label.show();
      this.element.css({top: this.options.inputOffsetTop});
    }
    this.active = true;
  };

  FluidLabel.prototype.hideLabel = function (animation) {
    animation = animation !== false;
    if (animation !== false) {
      this.label.fadeOut(this.options.animationDuration);
      this.element.animate({top: 0}, this.options.animationDuration);
    } else {
      this.label.hide();
      this.element.css({top: 0});
    }
    this.active = false;
  };

  FluidLabel.prototype.onFocused = function () {
    this.container.addClass(this.options.focusClass);
  };

  FluidLabel.prototype.onBlurred = function () {
    this.container.removeClass(this.options.focusClass);
  };

  $.fn.fluidLabel = function (options) {
    return this.each(function () {
      $(this).attr('fluid-label', new FluidLabel(this, options));
    });
  };
})(jQuery);
