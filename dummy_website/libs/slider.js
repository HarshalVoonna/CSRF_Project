function Slider( container, nav ) {
	this.container = container;
	this.nav = nav;

	this.imgs = this.container.find('.item');
	this.imgWidth = $(this.imgs[0]).width(); // 600
	this.imgsLen = this.imgs.length;

	this.count = 1;
}

Slider.prototype.transition = function(current,next) {
	// 内容更新
	next.css("margin-left","0px");
	current.after(next);
	current.animate({
		'margin-left': -(this.imgWidth)
	});
	// 导航更新
	this.nav.find('a').removeClass('act');
	this.nav.find('a[data-id='+this.count+']').addClass('act');
};

Slider.prototype.show = function(id) {
	var current = this._findItem();
	this.count = id || (this.count%this.imgsLen)+1;
	var next = this._findItem();
	this.transition(current,next);
};

Slider.prototype._findItem = function() {
	return this.container.find('div[data-id='+this.count+']').parent();
}
